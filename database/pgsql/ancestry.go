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

	findAncestryLayerHashes = `
		SELECT layer.hash, ancestry_layer.ancestry_index
		FROM layer, ancestry_layer
		WHERE ancestry_layer.ancestry_id = $1
			AND ancestry_layer.layer_id = layer.id
		ORDER BY ancestry_layer.ancestry_index ASC`

	findAncestryFeatures = `
		SELECT namespace.name, namespace.version_format, feature.name, 
			feature.version, feature.source_name, feature.source_version, feature.version_format,
			ancestry_layer.ancestry_index, ancestry_feature.feature_detector_id,
			ancestry_feature.namespace_detector_id
		FROM namespace, feature, namespaced_feature, ancestry_layer, ancestry_feature
		WHERE ancestry_layer.ancestry_id = $1
			AND ancestry_feature.ancestry_layer_id = ancestry_layer.id
			AND ancestry_feature.namespaced_feature_id = namespaced_feature.id
			AND namespaced_feature.feature_id = feature.id
			AND namespaced_feature.namespace_id = namespace.id`

	findAncestryID       = `SELECT id FROM ancestry WHERE name = $1`
	removeAncestry       = `DELETE FROM ancestry WHERE name = $1`
	insertAncestryLayers = `
		INSERT INTO ancestry_layer (ancestry_id, ancestry_index, layer_id) VALUES ($1, $2, $3)
		RETURNING id`
	insertAncestryFeatures = `
		INSERT INTO ancestry_feature
		(ancestry_layer_id, namespaced_feature_id, feature_detector_id, namespace_detector_id) VALUES
		($1, $2, $3, $4)`
)

func (tx *pgSession) FindAncestry(name string) (database.Ancestry, bool, error) {
	var (
		ancestry = database.Ancestry{Name: name}
		err      error
	)

	id, ok, err := tx.findAncestryID(name)
	if !ok || err != nil {
		return ancestry, ok, err
	}

	if ancestry.By, err = tx.findAncestryDetectors(id); err != nil {
		return ancestry, false, err
	}

	if ancestry.Layers, err = tx.findAncestryLayers(id); err != nil {
		return ancestry, false, err
	}

	return ancestry, true, nil
}

func (tx *pgSession) UpsertAncestry(ancestry database.Ancestry) error {
	if !ancestry.Valid() {
		return database.ErrInvalidParameters
	}

	if err := tx.removeAncestry(ancestry.Name); err != nil {
		return err
	}

	id, err := tx.insertAncestry(ancestry.Name)
	if err != nil {
		return err
	}

	detectorIDs, err := tx.findDetectorIDs(ancestry.By)
	if err != nil {
		return err
	}

	// insert ancestry metadata
	if err := tx.insertAncestryDetectors(id, detectorIDs); err != nil {
		return err
	}

	layers := make([]string, 0, len(ancestry.Layers))
	for _, layer := range ancestry.Layers {
		layers = append(layers, layer.Hash)
	}

	layerIDs, ok, err := tx.findLayerIDs(layers)
	if err != nil {
		return err
	}

	if !ok {
		log.Error("layer cannot be found, this indicates that the internal logic of calling UpsertAncestry is wrong or the database is corrupted.")
		return database.ErrMissingEntities
	}

	ancestryLayerIDs, err := tx.insertAncestryLayers(id, layerIDs)
	if err != nil {
		return err
	}

	for i, id := range ancestryLayerIDs {
		if err := tx.insertAncestryFeatures(id, ancestry.Layers[i]); err != nil {
			return err
		}
	}

	return nil
}

func (tx *pgSession) insertAncestry(name string) (int64, error) {
	var id int64
	err := tx.QueryRow(insertAncestry, name).Scan(&id)
	if err != nil {
		if isErrUniqueViolation(err) {
			return 0, handleError("insertAncestry", errors.New("other Go-routine is processing this ancestry (skip)"))
		}

		return 0, handleError("insertAncestry", err)
	}

	log.WithFields(log.Fields{"ancestry": name, "id": id}).Debug("database: inserted ancestry")
	return id, nil
}

func (tx *pgSession) findAncestryID(name string) (int64, bool, error) {
	var id sql.NullInt64
	if err := tx.QueryRow(findAncestryID, name).Scan(&id); err != nil {
		if err == sql.ErrNoRows {
			return 0, false, nil
		}

		return 0, false, handleError("findAncestryID", err)
	}

	return id.Int64, true, nil
}

func (tx *pgSession) removeAncestry(name string) error {
	result, err := tx.Exec(removeAncestry, name)
	if err != nil {
		return handleError("removeAncestry", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return handleError("removeAncestry", err)
	}

	if affected != 0 {
		log.WithField("ancestry", name).Debug("removed ancestry")
	}

	return nil
}

func (tx *pgSession) findAncestryLayers(id int64) ([]database.AncestryLayer, error) {
	detectors, err := tx.findAllDetectors()
	if err != nil {
		return nil, err
	}

	layerMap, err := tx.findAncestryLayerHashes(id)
	if err != nil {
		return nil, err
	}

	log.WithField("map", layerMap).Debug("found layer hashes")
	featureMap, err := tx.findAncestryFeatures(id, detectors)
	if err != nil {
		return nil, err
	}

	layers := make([]database.AncestryLayer, len(layerMap))
	for index, layer := range layerMap {
		// index MUST match the ancestry layer slice index.
		if layers[index].Hash == "" && len(layers[index].Features) == 0 {
			layers[index] = database.AncestryLayer{
				Hash:     layer,
				Features: featureMap[index],
			}
		} else {
			log.WithFields(log.Fields{
				"ancestry ID":               id,
				"duplicated ancestry index": index,
			}).WithError(database.ErrInconsistent).Error("ancestry layers with same ancestry_index is not allowed")
			return nil, database.ErrInconsistent
		}
	}

	return layers, nil
}

func (tx *pgSession) findAncestryLayerHashes(ancestryID int64) (map[int64]string, error) {
	// retrieve layer indexes and hashes
	rows, err := tx.Query(findAncestryLayerHashes, ancestryID)
	if err != nil {
		return nil, handleError("findAncestryLayerHashes", err)
	}

	layerHashes := map[int64]string{}
	for rows.Next() {
		var (
			hash  string
			index int64
		)

		if err = rows.Scan(&hash, &index); err != nil {
			return nil, handleError("findAncestryLayerHashes", err)
		}

		if _, ok := layerHashes[index]; ok {
			// one ancestry index should correspond to only one layer
			return nil, database.ErrInconsistent
		}

		layerHashes[index] = hash
	}

	return layerHashes, nil
}

func (tx *pgSession) findAncestryFeatures(ancestryID int64, detectors detectorMap) (map[int64][]database.AncestryFeature, error) {
	// ancestry_index -> ancestry features
	featureMap := make(map[int64][]database.AncestryFeature)
	// retrieve ancestry layer's namespaced features
	rows, err := tx.Query(findAncestryFeatures, ancestryID)
	if err != nil {
		return nil, handleError("findAncestryFeatures", err)
	}

	defer rows.Close()

	for rows.Next() {
		var (
			featureDetectorID   int64
			namespaceDetectorID int64
			feature             database.NamespacedFeature
			// index is used to determine which layer the feature belongs to.
			index sql.NullInt64
		)

		if err := rows.Scan(
			&feature.Namespace.Name,
			&feature.Namespace.VersionFormat,
			&feature.Feature.Name,
			&feature.Feature.Version,
			&feature.Feature.SourceName,
			&feature.Feature.SourceVersion,
			&feature.Feature.VersionFormat,
			&index,
			&featureDetectorID,
			&namespaceDetectorID,
		); err != nil {
			return nil, handleError("findAncestryFeatures", err)
		}

		if feature.Feature.VersionFormat != feature.Namespace.VersionFormat {
			// Feature must have the same version format as the associated
			// namespace version format.
			return nil, database.ErrInconsistent
		}

		fDetector, ok := detectors.byID[featureDetectorID]
		if !ok {
			return nil, database.ErrInconsistent
		}

		nsDetector, ok := detectors.byID[namespaceDetectorID]
		if !ok {
			return nil, database.ErrInconsistent
		}

		featureMap[index.Int64] = append(featureMap[index.Int64], database.AncestryFeature{
			NamespacedFeature: feature,
			FeatureBy:         fDetector,
			NamespaceBy:       nsDetector,
		})
	}

	return featureMap, nil
}

// insertAncestryLayers inserts the ancestry layers along with its content into
// the database. The layers are 0 based indexed in the original order.
func (tx *pgSession) insertAncestryLayers(ancestryID int64, layers []int64) ([]int64, error) {
	stmt, err := tx.Prepare(insertAncestryLayers)
	if err != nil {
		return nil, handleError("insertAncestryLayers", err)
	}

	ancestryLayerIDs := []int64{}
	for index, layerID := range layers {
		var ancestryLayerID sql.NullInt64
		if err := stmt.QueryRow(ancestryID, index, layerID).Scan(&ancestryLayerID); err != nil {
			return nil, handleError("insertAncestryLayers", commonerr.CombineErrors(err, stmt.Close()))
		}

		if !ancestryLayerID.Valid {
			return nil, database.ErrInconsistent
		}

		ancestryLayerIDs = append(ancestryLayerIDs, ancestryLayerID.Int64)
	}

	if err := stmt.Close(); err != nil {
		return nil, handleError("insertAncestryLayers", err)
	}

	return ancestryLayerIDs, nil
}

func (tx *pgSession) insertAncestryFeatures(ancestryLayerID int64, layer database.AncestryLayer) error {
	detectors, err := tx.findAllDetectors()
	if err != nil {
		return err
	}

	nsFeatureIDs, err := tx.findNamespacedFeatureIDs(layer.GetFeatures())
	if err != nil {
		return err
	}

	// find the detectors for each feature
	stmt, err := tx.Prepare(insertAncestryFeatures)
	if err != nil {
		return handleError("insertAncestryFeatures", err)
	}

	defer stmt.Close()

	for index, id := range nsFeatureIDs {
		namespaceDetectorID, ok := detectors.byValue[layer.Features[index].NamespaceBy]
		if !ok {
			return database.ErrMissingEntities
		}

		featureDetectorID, ok := detectors.byValue[layer.Features[index].FeatureBy]
		if !ok {
			return database.ErrMissingEntities
		}

		if _, err := stmt.Exec(ancestryLayerID, id, featureDetectorID, namespaceDetectorID); err != nil {
			return handleError("insertAncestryFeatures", commonerr.CombineErrors(err, stmt.Close()))
		}
	}

	return nil
}
