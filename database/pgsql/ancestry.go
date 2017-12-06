package pgsql

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/lib/pq"
	log "github.com/sirupsen/logrus"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/pkg/commonerr"
)

func (tx *pgSession) UpsertAncestry(ancestry database.Ancestry, features []database.NamespacedFeature, processedBy database.Processors) error {
	if ancestry.Name == "" {
		log.Warning("Empty ancestry name is not allowed")
		return commonerr.NewBadRequestError("could not insert an ancestry with empty name")
	}

	if len(ancestry.Layers) == 0 {
		log.Warning("Empty ancestry is not allowed")
		return commonerr.NewBadRequestError("could not insert an ancestry with 0 layers")
	}

	err := tx.deleteAncestry(ancestry.Name)
	if err != nil {
		return err
	}

	var ancestryID int64
	err = tx.QueryRow(insertAncestry, ancestry.Name).Scan(&ancestryID)
	if err != nil {
		if isErrUniqueViolation(err) {
			return handleError("insertAncestry", errors.New("Other Go-routine is processing this ancestry (skip)."))
		}
		return handleError("insertAncestry", err)
	}

	err = tx.insertAncestryLayers(ancestryID, ancestry.Layers)
	if err != nil {
		return err
	}

	err = tx.insertAncestryFeatures(ancestryID, features)
	if err != nil {
		return err
	}

	return tx.persistProcessors(persistAncestryLister,
		"persistAncestryLister",
		persistAncestryDetector,
		"persistAncestryDetector",
		ancestryID, processedBy)
}

func (tx *pgSession) FindAncestry(name string) (database.Ancestry, database.Processors, bool, error) {
	ancestry := database.Ancestry{Name: name}
	processed := database.Processors{}

	var ancestryID int64
	err := tx.QueryRow(searchAncestry, name).Scan(&ancestryID)
	if err != nil {
		if err == sql.ErrNoRows {
			return ancestry, processed, false, nil
		}
		return ancestry, processed, false, handleError("searchAncestry", err)
	}

	ancestry.Layers, err = tx.findAncestryLayers(ancestryID)
	if err != nil {
		return ancestry, processed, false, err
	}

	processed.Detectors, err = tx.findProcessors(searchAncestryDetectors, "searchAncestryDetectors", "detector", ancestryID)
	if err != nil {
		return ancestry, processed, false, err
	}

	processed.Listers, err = tx.findProcessors(searchAncestryListers, "searchAncestryListers", "lister", ancestryID)
	if err != nil {
		return ancestry, processed, false, err
	}

	return ancestry, processed, true, nil
}

func (tx *pgSession) FindAncestryFeatures(name string) (database.AncestryWithFeatures, bool, error) {
	var (
		awf database.AncestryWithFeatures
		ok  bool
		err error
	)
	awf.Ancestry, awf.ProcessedBy, ok, err = tx.FindAncestry(name)
	if err != nil {
		return awf, false, err
	}

	if !ok {
		return awf, false, nil
	}

	rows, err := tx.Query(searchAncestryFeatures, name)
	if err != nil {
		return awf, false, handleError("searchAncestryFeatures", err)
	}

	for rows.Next() {
		nf := database.NamespacedFeature{}
		err := rows.Scan(&nf.Namespace.Name, &nf.Namespace.VersionFormat, &nf.Feature.Name, &nf.Feature.Version)
		if err != nil {
			return awf, false, handleError("searchAncestryFeatures", err)
		}
		nf.Feature.VersionFormat = nf.Namespace.VersionFormat
		awf.Features = append(awf.Features, nf)
	}

	return awf, true, nil
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
		err := rows.Scan(&layer.Hash)
		if err != nil {
			return nil, handleError("searchAncestryLayer", err)
		}
		layers = append(layers, layer)
	}
	return layers, nil
}

func (tx *pgSession) insertAncestryLayers(ancestryID int64, layers []database.Layer) error {
	layerIDs := map[string]sql.NullInt64{}
	for _, l := range layers {
		layerIDs[l.Hash] = sql.NullInt64{}
	}

	layerHashes := []string{}
	for hash := range layerIDs {
		layerHashes = append(layerHashes, hash)
	}

	rows, err := tx.Query(searchLayerIDs, pq.Array(layerHashes))
	if err != nil {
		return handleError("searchLayerIDs", err)
	}

	for rows.Next() {
		var (
			layerID   sql.NullInt64
			layerName string
		)
		err := rows.Scan(&layerID, &layerName)
		if err != nil {
			return handleError("searchLayerIDs", err)
		}
		layerIDs[layerName] = layerID
	}

	notFound := []string{}
	for hash, id := range layerIDs {
		if !id.Valid {
			notFound = append(notFound, hash)
		}
	}

	if len(notFound) > 0 {
		return handleError("searchLayerIDs", fmt.Errorf("Layer %s is not found in database", strings.Join(notFound, ",")))
	}

	//TODO(Sida): use bulk insert.
	stmt, err := tx.Prepare(insertAncestryLayer)
	if err != nil {
		return handleError("insertAncestryLayer", err)
	}

	defer stmt.Close()
	for index, layer := range layers {
		_, err := stmt.Exec(ancestryID, index, layerIDs[layer.Hash].Int64)
		if err != nil {
			return handleError("insertAncestryLayer", commonerr.CombineErrors(err, stmt.Close()))
		}
	}

	return nil
}

func (tx *pgSession) insertAncestryFeatures(ancestryID int64, features []database.NamespacedFeature) error {
	featureIDs, err := tx.findNamespacedFeatureIDs(features)
	if err != nil {
		return err
	}

	//TODO(Sida): use bulk insert.
	stmtFeatures, err := tx.Prepare(insertAncestryFeature)
	if err != nil {
		return handleError("insertAncestryFeature", err)
	}

	defer stmtFeatures.Close()

	for _, id := range featureIDs {
		if !id.Valid {
			return errors.New("requested namespaced feature is not in database")
		}

		_, err := stmtFeatures.Exec(ancestryID, id)
		if err != nil {
			return handleError("insertAncestryFeature", err)
		}
	}

	return nil
}
