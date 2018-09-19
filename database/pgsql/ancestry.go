package pgsql

import (
	"database/sql"
	"errors"

	log "github.com/sirupsen/logrus"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/pkg/commonerr"
)

const (
	insertAncestry = `
		INSERT INTO ancestry (name) VALUES ($1) RETURNING id`

	searchAncestryLayer = `
		SELECT layer.hash, layer.id, ancestry_layer.ancestry_index
		FROM layer, ancestry_layer
		WHERE ancestry_layer.ancestry_id = $1
			AND ancestry_layer.layer_id = layer.id
		ORDER BY ancestry_layer.ancestry_index ASC`

	searchAncestryFeatures = `
		SELECT namespace.name, namespace.version_format, feature.name, feature.version, feature.version_format, ancestry_layer.ancestry_index
		FROM namespace, feature, namespaced_feature, ancestry_layer, ancestry_feature
		WHERE ancestry_layer.ancestry_id = $1
			AND ancestry_feature.ancestry_layer_id = ancestry_layer.id
			AND ancestry_feature.namespaced_feature_id = namespaced_feature.id
			AND namespaced_feature.feature_id = feature.id
			AND namespaced_feature.namespace_id = namespace.id`

	searchAncestry      = `SELECT id FROM ancestry WHERE name = $1`
	removeAncestry      = `DELETE FROM ancestry WHERE name = $1`
	insertAncestryLayer = `
		INSERT INTO ancestry_layer (ancestry_id, ancestry_index, layer_id) VALUES
		($1, $2, (SELECT layer.id FROM layer WHERE hash = $3 LIMIT 1))
		RETURNING id`
	insertAncestryLayerFeature = `
		INSERT INTO ancestry_feature
		(ancestry_layer_id, namespaced_feature_id, feature_detector_id, namespace_detector_id) VALUES
		($1, $2, $3, $4)`
)

type ancestryLayerWithID struct {
	database.AncestryLayer

	layerID int64
}

func (tx *pgSession) UpsertAncestry(ancestry database.Ancestry) error {
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

func (tx *pgSession) findAncestryID(name string) (int64, bool, error) {
	var id sql.NullInt64
	if err := tx.QueryRow(searchAncestry, name).Scan(&id); err != nil {
		if err == sql.ErrNoRows {
			return 0, false, nil
		}

		return 0, false, handleError("searchAncestry", err)
	}

	return id.Int64, true, nil
}

func (tx *pgSession) findAncestryProcessors(id int64) (database.Processors, error) {
	var (
		processors database.Processors
		err        error
	)

	if processors.Detectors, err = tx.findProcessors(searchAncestryDetectors, id); err != nil {
		return processors, handleError("searchAncestryDetectors", err)
	}

	if processors.Listers, err = tx.findProcessors(searchAncestryListers, id); err != nil {
		return processors, handleError("searchAncestryListers", err)
	}

	return processors, err
}

func (tx *pgSession) FindAncestry(name string) (database.Ancestry, bool, error) {
	var (
		ancestry = database.Ancestry{Name: name}
		err      error
	)

	id, ok, err := tx.findAncestryID(name)
	if !ok || err != nil {
		return ancestry, ok, err
	}

	if ancestry.ProcessedBy, err = tx.findAncestryProcessors(id); err != nil {
		return ancestry, false, err
	}

	if ancestry.Layers, err = tx.findAncestryLayers(id); err != nil {
		return ancestry, false, err
	}

	return ancestry, true, nil
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

func (tx *pgSession) findProcessors(query string, id int64) ([]string, error) {
	var (
		processors []string
		processor  string
	)

	rows, err := tx.Query(query, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}

		return nil, err
	}

	for rows.Next() {
		if err := rows.Scan(&processor); err != nil {
			return nil, err
		}

		processors = append(processors, processor)
	}

	return processors, nil
}

func (tx *pgSession) findAncestryLayers(id int64) ([]database.AncestryLayer, error) {
	var (
		err  error
		rows *sql.Rows
		// layer index -> Ancestry Layer + Layer ID
		layers = map[int64]ancestryLayerWithID{}
		// layer index -> layer-wise features
		features       = map[int64][]database.NamespacedFeature{}
		ancestryLayers []database.AncestryLayer
	)

	// retrieve ancestry layer metadata
	if rows, err = tx.Query(searchAncestryLayer, id); err != nil {
		return nil, handleError("searchAncestryLayer", err)
	}

	for rows.Next() {
		var (
			layer database.AncestryLayer
			index sql.NullInt64
			id    sql.NullInt64
		)

		if err = rows.Scan(&layer.Hash, &id, &index); err != nil {
			return nil, handleError("searchAncestryLayer", err)
		}

		if !index.Valid || !id.Valid {
			panic("null ancestry ID or ancestry index violates database constraints")
		}

		if _, ok := layers[index.Int64]; ok {
			// one ancestry index should correspond to only one layer
			return nil, database.ErrInconsistent
		}

		layers[index.Int64] = ancestryLayerWithID{layer, id.Int64}
	}

	for _, layer := range layers {
		if layer.ProcessedBy, err = tx.findLayerProcessors(layer.layerID); err != nil {
			return nil, err
		}
	}

	// retrieve ancestry layer's namespaced features
	if rows, err = tx.Query(searchAncestryFeatures, id); err != nil {
		return nil, handleError("searchAncestryFeatures", err)
	}

	for rows.Next() {
		var (
			feature database.NamespacedFeature
			// index is used to determine which layer the feature belongs to.
			index sql.NullInt64
		)

		if err := rows.Scan(
			&feature.Namespace.Name,
			&feature.Namespace.VersionFormat,
			&feature.Feature.Name,
			&feature.Feature.Version,
			&feature.Feature.VersionFormat,
			&index,
		); err != nil {
			return nil, handleError("searchAncestryFeatures", err)
		}

		if feature.Feature.VersionFormat != feature.Namespace.VersionFormat {
			// Feature must have the same version format as the associated
			// namespace version format.
			return nil, database.ErrInconsistent
		}

		features[index.Int64] = append(features[index.Int64], feature)
	}

	for index, layer := range layers {
		layer.DetectedFeatures = features[index]
		ancestryLayers = append(ancestryLayers, layer.AncestryLayer)
	}

	return ancestryLayers, nil
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
