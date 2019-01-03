// Copyright 2017 clair authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pgsql

import (
	"database/sql"
	"sort"

	"github.com/deckarep/golang-set"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/pkg/commonerr"
)

const (
	soiLayer = `
		WITH new_layer AS (
			INSERT INTO layer (hash)
			SELECT CAST ($1 AS VARCHAR)
			WHERE NOT EXISTS (SELECT id FROM layer WHERE hash = $1)
			RETURNING id
		)
		SELECT id FROM new_Layer
		UNION
		SELECT id FROM layer WHERE hash = $1`

	findLayerFeatures = `
		SELECT f.name, f.version, f.source_name, f.source_version, f.version_format, lf.detector_id
			FROM layer_feature AS lf, feature AS f
			WHERE lf.feature_id = f.id
				AND lf.layer_id = $1`

	findLayerNamespaces = `
		SELECT ns.name, ns.version_format, ln.detector_id
			FROM layer_namespace AS ln, namespace AS ns
			WHERE ln.namespace_id = ns.id
				AND ln.layer_id = $1`

	findLayerID = `SELECT id FROM layer WHERE hash = $1`
)

// dbLayerNamespace represents the layer_namespace table.
type dbLayerNamespace struct {
	layerID     int64
	namespaceID int64
	detectorID  int64
}

// dbLayerFeature represents the layer_feature table
type dbLayerFeature struct {
	layerID    int64
	featureID  int64
	detectorID int64
}

func (tx *pgSession) FindLayer(hash string) (database.Layer, bool, error) {
	layer := database.Layer{Hash: hash}
	if hash == "" {
		return layer, false, commonerr.NewBadRequestError("non empty layer hash is expected.")
	}

	layerID, ok, err := tx.findLayerID(hash)
	if err != nil || !ok {
		return layer, ok, err
	}

	detectorMap, err := tx.findAllDetectors()
	if err != nil {
		return layer, false, err
	}

	if layer.By, err = tx.findLayerDetectors(layerID); err != nil {
		return layer, false, err
	}

	if layer.Features, err = tx.findLayerFeatures(layerID, detectorMap); err != nil {
		return layer, false, err
	}

	if layer.Namespaces, err = tx.findLayerNamespaces(layerID, detectorMap); err != nil {
		return layer, false, err
	}

	return layer, true, nil
}

func sanitizePersistLayerInput(hash string, features []database.LayerFeature, namespaces []database.LayerNamespace, detectedBy []database.Detector) error {
	if hash == "" {
		return commonerr.NewBadRequestError("expected non-empty layer hash")
	}

	detectedBySet := mapset.NewSet()
	for _, d := range detectedBy {
		detectedBySet.Add(d)
	}

	for _, f := range features {
		if !detectedBySet.Contains(f.By) {
			return database.ErrInvalidParameters
		}
	}

	for _, n := range namespaces {
		if !detectedBySet.Contains(n.By) {
			return database.ErrInvalidParameters
		}
	}

	return nil
}

// PersistLayer saves the content of a layer to the database.
func (tx *pgSession) PersistLayer(hash string, features []database.LayerFeature, namespaces []database.LayerNamespace, detectedBy []database.Detector) error {
	var (
		err         error
		id          int64
		detectorIDs []int64
	)

	if err = sanitizePersistLayerInput(hash, features, namespaces, detectedBy); err != nil {
		return err
	}

	if id, err = tx.soiLayer(hash); err != nil {
		return err
	}

	if detectorIDs, err = tx.findDetectorIDs(detectedBy); err != nil {
		if err == commonerr.ErrNotFound {
			return database.ErrMissingEntities
		}

		return err
	}

	if err = tx.persistLayerDetectors(id, detectorIDs); err != nil {
		return err
	}

	if err = tx.persistAllLayerFeatures(id, features); err != nil {
		return err
	}

	if err = tx.persistAllLayerNamespaces(id, namespaces); err != nil {
		return err
	}

	return nil
}

func (tx *pgSession) persistAllLayerNamespaces(layerID int64, namespaces []database.LayerNamespace) error {
	detectorMap, err := tx.findAllDetectors()
	if err != nil {
		return err
	}

	// TODO(sidac): This kind of type conversion is very useless and wasteful,
	// we need interfaces around the database models to reduce these kind of
	// operations.
	rawNamespaces := make([]database.Namespace, 0, len(namespaces))
	for _, ns := range namespaces {
		rawNamespaces = append(rawNamespaces, ns.Namespace)
	}

	rawNamespaceIDs, err := tx.findNamespaceIDs(rawNamespaces)
	if err != nil {
		return err
	}

	dbLayerNamespaces := make([]dbLayerNamespace, 0, len(namespaces))
	for i, ns := range namespaces {
		detectorID := detectorMap.byValue[ns.By]
		namespaceID := rawNamespaceIDs[i].Int64
		if !rawNamespaceIDs[i].Valid {
			return database.ErrMissingEntities
		}

		dbLayerNamespaces = append(dbLayerNamespaces, dbLayerNamespace{layerID, namespaceID, detectorID})
	}

	return tx.persistLayerNamespaces(dbLayerNamespaces)
}

func (tx *pgSession) persistAllLayerFeatures(layerID int64, features []database.LayerFeature) error {
	detectorMap, err := tx.findAllDetectors()
	if err != nil {
		return err
	}

	rawFeatures := make([]database.Feature, 0, len(features))
	for _, f := range features {
		rawFeatures = append(rawFeatures, f.Feature)
	}

	featureIDs, err := tx.findFeatureIDs(rawFeatures)
	if err != nil {
		return err
	}

	dbFeatures := make([]dbLayerFeature, 0, len(features))
	for i, f := range features {
		detectorID := detectorMap.byValue[f.By]
		featureID := featureIDs[i].Int64
		if !featureIDs[i].Valid {
			return database.ErrMissingEntities
		}

		dbFeatures = append(dbFeatures, dbLayerFeature{layerID, featureID, detectorID})
	}

	if err := tx.persistLayerFeatures(dbFeatures); err != nil {
		return err
	}

	return nil
}

func (tx *pgSession) persistLayerFeatures(features []dbLayerFeature) error {
	if len(features) == 0 {
		return nil
	}

	sort.Slice(features, func(i, j int) bool {
		return features[i].featureID < features[j].featureID
	})
	keys := make([]interface{}, 0, len(features)*3)
	for _, f := range features {
		keys = append(keys, f.layerID, f.featureID, f.detectorID)
	}

	_, err := tx.Exec(queryPersistLayerFeature(len(features)), keys...)
	if err != nil {
		return handleError("queryPersistLayerFeature", err)
	}
	return nil
}

func (tx *pgSession) persistLayerNamespaces(namespaces []dbLayerNamespace) error {
	if len(namespaces) == 0 {
		return nil
	}

	// for every bulk persist operation, the input data should be sorted.
	sort.Slice(namespaces, func(i, j int) bool {
		return namespaces[i].namespaceID < namespaces[j].namespaceID
	})

	keys := make([]interface{}, 0, len(namespaces)*3)
	for _, row := range namespaces {
		keys = append(keys, row.layerID, row.namespaceID, row.detectorID)
	}

	_, err := tx.Exec(queryPersistLayerNamespace(len(namespaces)), keys...)
	if err != nil {
		return handleError("queryPersistLayerNamespace", err)
	}

	return nil
}

func (tx *pgSession) findLayerNamespaces(layerID int64, detectors detectorMap) ([]database.LayerNamespace, error) {
	rows, err := tx.Query(findLayerNamespaces, layerID)
	if err != nil {
		return nil, handleError("findLayerNamespaces", err)
	}

	namespaces := []database.LayerNamespace{}
	for rows.Next() {
		var (
			namespace  database.LayerNamespace
			detectorID int64
		)

		if err := rows.Scan(&namespace.Name, &namespace.VersionFormat, &detectorID); err != nil {
			return nil, err
		}

		namespace.By = detectors.byID[detectorID]
		namespaces = append(namespaces, namespace)
	}

	return namespaces, nil
}

func (tx *pgSession) findLayerFeatures(layerID int64, detectors detectorMap) ([]database.LayerFeature, error) {
	rows, err := tx.Query(findLayerFeatures, layerID)
	if err != nil {
		return nil, handleError("findLayerFeatures", err)
	}
	defer rows.Close()

	features := []database.LayerFeature{}
	for rows.Next() {
		var (
			detectorID int64
			feature    database.LayerFeature
		)
		if err := rows.Scan(&feature.Name, &feature.Version, &feature.SourceName, &feature.SourceVersion,
			&feature.VersionFormat, &detectorID); err != nil {
			return nil, handleError("findLayerFeatures", err)
		}

		feature.By = detectors.byID[detectorID]
		features = append(features, feature)
	}

	return features, nil
}

func (tx *pgSession) findLayerID(hash string) (int64, bool, error) {
	var layerID int64
	err := tx.QueryRow(findLayerID, hash).Scan(&layerID)
	if err != nil {
		if err == sql.ErrNoRows {
			return layerID, false, nil
		}

		return layerID, false, handleError("findLayerID", err)
	}

	return layerID, true, nil
}

func (tx *pgSession) findLayerIDs(hashes []string) ([]int64, bool, error) {
	layerIDs := make([]int64, 0, len(hashes))
	for _, hash := range hashes {
		id, ok, err := tx.findLayerID(hash)
		if !ok {
			return nil, false, nil
		}

		if err != nil {
			return nil, false, err
		}

		layerIDs = append(layerIDs, id)
	}

	return layerIDs, true, nil
}

func (tx *pgSession) soiLayer(hash string) (int64, error) {
	var id int64
	if err := tx.QueryRow(soiLayer, hash).Scan(&id); err != nil {
		return 0, handleError("soiLayer", err)
	}

	return id, nil
}
