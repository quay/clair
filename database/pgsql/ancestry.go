package pgsql

import (
	"database/sql"
	"errors"

	log "github.com/sirupsen/logrus"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/pkg/commonerr"
)

func (tx *pgSession) UpsertAncestry(ancestry database.AncestryWithContent) error {
	if ancestry.Name == "" {
		log.Error("Empty ancestry name is not allowed")
		return commonerr.NewBadRequestError("could not insert an ancestry with empty name")
	}

	if len(ancestry.Layers) == 0 {
		log.Error("Empty ancestry is not allowed")
		return commonerr.NewBadRequestError("could not insert an ancestry with 0 layers")
	}

	if err := tx.deleteAncestry(ancestry.Name); err != nil {
		return err
	}

	var ancestryID int64
	if err := tx.QueryRow(insertAncestry, ancestry.Name).Scan(&ancestryID); err != nil {
		if isErrUniqueViolation(err) {
			return handleError("insertAncestry", errors.New("other Go-routine is processing this ancestry (skip)"))
		}
		return handleError("insertAncestry", err)
	}

	if err := tx.insertAncestryLayers(ancestryID, ancestry.Layers); err != nil {
		return err
	}

	return tx.persistProcessors(persistAncestryLister,
		"persistAncestryLister",
		persistAncestryDetector,
		"persistAncestryDetector",
		ancestryID, ancestry.ProcessedBy)
}

func (tx *pgSession) FindAncestry(name string) (database.Ancestry, bool, error) {
	var (
		ancestryID int64
		ancestry   = database.Ancestry{Name: name}
		err        error
	)

	if err = tx.QueryRow(searchAncestry, name).Scan(&ancestryID); err != nil {
		if err == sql.ErrNoRows {
			return ancestry, false, nil
		}
		return ancestry, false, handleError("searchAncestry", err)
	}

	if ancestry.Layers, err = tx.findAncestryLayers(ancestryID); err != nil {
		return ancestry, false, err
	}

	if ancestry.ProcessedBy.Detectors, err = tx.findProcessors(searchAncestryDetectors, "searchAncestryDetectors", "detector", ancestryID); err != nil {
		return ancestry, false, err
	}

	if ancestry.ProcessedBy.Listers, err = tx.findProcessors(searchAncestryListers, "searchAncestryListers", "lister", ancestryID); err != nil {
		return ancestry, false, err
	}

	return ancestry, true, nil
}

func (tx *pgSession) FindAncestryWithContent(name string) (database.AncestryWithContent, bool, error) {
	var (
		ancestryContent database.AncestryWithContent
		isValid         bool
		err             error
	)

	if ancestryContent.Ancestry, isValid, err = tx.FindAncestry(name); err != nil || !isValid {
		return ancestryContent, isValid, err
	}

	rows, err := tx.Query(searchAncestryFeatures, name)
	if err != nil {
		return ancestryContent, false, handleError("searchAncestryFeatures", err)
	}

	features := map[int][]database.NamespacedFeature{}
	for rows.Next() {
		var (
			feature database.NamespacedFeature
			// layerIndex is used to determine which layer the namespaced feature belongs to.
			layerIndex sql.NullInt64
		)

		if err := rows.Scan(&feature.Namespace.Name,
			&feature.Namespace.VersionFormat,
			&feature.Feature.Name, &feature.Feature.Version,
			&layerIndex); err != nil {
			return ancestryContent, false, handleError("searchAncestryFeatures", err)
		}

		feature.Feature.VersionFormat = feature.Namespace.VersionFormat // This looks strange.
		features[int(layerIndex.Int64)] = append(features[int(layerIndex.Int64)], feature)
	}

	// By the assumption of Ancestry Layer Index, we have the ancestry's layer
	// index corresponding to the index in the array.
	for index, layer := range ancestryContent.Ancestry.Layers {
		ancestryLayer := database.AncestryLayer{Layer: layer}
		ancestryLayer.DetectedFeatures, _ = features[index]
		ancestryContent.Layers = append(ancestryContent.Layers, ancestryLayer)
	}

	return ancestryContent, true, nil
}

func (tx *pgSession) deleteAncestry(name string) error {
	result, err := tx.Exec(removeAncestry, name)
	if err != nil {
		return handleError("removeAncestry", err)
	}

	_, err = result.RowsAffected()
	if err != nil {
		return handleError("removeAncestry", err)
	}

	return nil
}

func (tx *pgSession) findProcessors(query, queryName, processorType string, id int64) ([]string, error) {
	rows, err := tx.Query(query, id)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Warning("No " + processorType + " are used")
			return nil, nil
		}
		return nil, handleError(queryName, err)
	}

	var (
		processors []string
		processor  string
	)

	for rows.Next() {
		err := rows.Scan(&processor)
		if err != nil {
			return nil, handleError(queryName, err)
		}
		processors = append(processors, processor)
	}

	return processors, nil
}

func (tx *pgSession) findAncestryLayers(ancestryID int64) ([]database.Layer, error) {
	rows, err := tx.Query(searchAncestryLayer, ancestryID)
	if err != nil {
		return nil, handleError("searchAncestryLayer", err)
	}

	layers := []database.Layer{}
	for rows.Next() {
		var layer database.Layer
		if err := rows.Scan(&layer.Hash); err != nil {
			return nil, handleError("searchAncestryLayer", err)
		}

		layers = append(layers, layer)
	}

	return layers, nil
}

// insertAncestryLayers inserts the ancestry layers along with its content into
// the database. The layers are 0 based indexed in the original order.
func (tx *pgSession) insertAncestryLayers(ancestryID int64, layers []database.AncestryLayer) error {
	//TODO(Sida): use bulk insert.
	stmt, err := tx.Prepare(insertAncestryLayer)
	if err != nil {
		return handleError("insertAncestryLayer", err)
	}

	ancestryLayerIDs := []sql.NullInt64{}
	for index, layer := range layers {
		var ancestryLayerID sql.NullInt64
		if err := stmt.QueryRow(ancestryID, index, layer.Hash).Scan(&ancestryLayerID); err != nil {
			return handleError("insertAncestryLayer", commonerr.CombineErrors(err, stmt.Close()))
		}

		ancestryLayerIDs = append(ancestryLayerIDs, ancestryLayerID)
	}

	if err := stmt.Close(); err != nil {
		return handleError("Failed to close insertAncestryLayer statement", err)
	}

	stmt, err = tx.Prepare(insertAncestryLayerFeature)
	defer stmt.Close()

	for i, layer := range layers {
		var (
			nsFeatureIDs []sql.NullInt64
			layerID      = ancestryLayerIDs[i]
		)

		if nsFeatureIDs, err = tx.findNamespacedFeatureIDs(layer.DetectedFeatures); err != nil {
			return err
		}

		for _, id := range nsFeatureIDs {
			if _, err := stmt.Exec(layerID, id); err != nil {
				return handleError("insertAncestryLayerFeature", commonerr.CombineErrors(err, stmt.Close()))
			}
		}

	}

	return nil
}
