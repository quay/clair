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

	searchLayerFeatures = `
		SELECT feature_id, detector_id
			FROM layer_feature
			WHERE layer_id = $1`

	searchLayerNamespaces = `
		SELECT namespace.Name, namespace.version_format 
		FROM namespace, layer_namespace 
		WHERE layer_namespace.layer_id = $1 
			AND layer_namespace.namespace_id = namespace.id`

	searchLayer = `SELECT id FROM layer WHERE hash = $1`
)
	if err != nil {
		return layer, false, err
	}

	if !ok {
		return layer, false, nil
	}

	layer.Features, err = tx.findLayerFeatures(layerID)
	layer.Namespaces, err = tx.findLayerNamespaces(layerID)
	return layer, true, nil
}

func (tx *pgSession) persistLayer(hash string) (int64, error) {
	if hash == "" {
		return -1, commonerr.NewBadRequestError("Empty Layer Hash is not allowed")
	}

	id := sql.NullInt64{}
	if err := tx.QueryRow(soiLayer, hash).Scan(&id); err != nil {
		return -1, handleError("queryPersistLayer", err)
	}

	if !id.Valid {
		panic("null layer.id violates database constraint")
	}

	return id.Int64, nil
}

// PersistLayer relates layer identified by hash with namespaces,
// features and processors provided. If the layer, namespaces, features are not
// in database, the function returns an error.
func (tx *pgSession) PersistLayer(hash string, namespaces []database.Namespace, features []database.Feature, processedBy database.Processors) error {
	if hash == "" {
		return commonerr.NewBadRequestError("Empty layer hash is not allowed")
	}

	var (
		err error
		id  int64
	)

	if id, err = tx.persistLayer(hash); err != nil {
		return err
	}

	if err = tx.persistLayerNamespace(id, namespaces); err != nil {
		return err
	}

	if err = tx.persistLayerFeatures(id, features); err != nil {
		return err
	}

	if err = tx.persistLayerDetectors(id, processedBy.Detectors); err != nil {
		return err
	}

	if err = tx.persistLayerListers(id, processedBy.Listers); err != nil {
		return err
	}

	return nil
}

func (tx *pgSession) persistLayerDetectors(id int64, detectors []string) error {
	if len(detectors) == 0 {
		return nil
	}

	// Sorting is needed before inserting into database to prevent deadlock.
	sort.Strings(detectors)
	keys := make([]interface{}, len(detectors)*2)
	for i, d := range detectors {
		keys[i*2] = id
		keys[i*2+1] = d
	}
	_, err := tx.Exec(queryPersistLayerDetectors(len(detectors)), keys...)
	if err != nil {
		return handleError("queryPersistLayerDetectors", err)
	}
	return nil
}

func (tx *pgSession) persistLayerListers(id int64, listers []string) error {
	if len(listers) == 0 {
		return nil
	}

	sort.Strings(listers)
	keys := make([]interface{}, len(listers)*2)
	for i, d := range listers {
		keys[i*2] = id
		keys[i*2+1] = d
	}

	_, err := tx.Exec(queryPersistLayerListers(len(listers)), keys...)
	if err != nil {
		return handleError("queryPersistLayerDetectors", err)
	}
	return nil
}

func (tx *pgSession) persistLayerFeatures(id int64, features []database.Feature) error {
	if len(features) == 0 {
		return nil
	}

	fIDs, err := tx.findFeatureIDs(features)
	if err != nil {
		return err
	}

	ids := make([]int, len(fIDs))
	for i, fID := range fIDs {
		if !fID.Valid {
			return errNamespaceNotFound
		}
		ids[i] = int(fID.Int64)
	}

	sort.IntSlice(ids).Sort()
	keys := make([]interface{}, len(features)*2)
	for i, fID := range ids {
		keys[i*2] = id
		keys[i*2+1] = fID
	}

	_, err = tx.Exec(queryPersistLayerFeature(len(features)), keys...)
	if err != nil {
		return handleError("queryPersistLayerFeature", err)
	}
	return nil
}

func (tx *pgSession) persistLayerNamespace(id int64, namespaces []database.Namespace) error {
	if len(namespaces) == 0 {
		return nil
	}

	nsIDs, err := tx.findNamespaceIDs(namespaces)
	if err != nil {
		return err
	}

	// for every bulk persist operation, the input data should be sorted.
	ids := make([]int, len(nsIDs))
	for i, nsID := range nsIDs {
		if !nsID.Valid {
			panic(errNamespaceNotFound)
		}
		ids[i] = int(nsID.Int64)
	}

	sort.IntSlice(ids).Sort()

	keys := make([]interface{}, len(namespaces)*2)
	for i, nsID := range ids {
		keys[i*2] = id
		keys[i*2+1] = nsID
	}

	_, err = tx.Exec(queryPersistLayerNamespace(len(namespaces)), keys...)
	if err != nil {
		return handleError("queryPersistLayerNamespace", err)
	}
	return nil
}

func (tx *pgSession) persistProcessors(listerQuery, listerQueryName, detectorQuery, detectorQueryName string, id int64, processors database.Processors) error {
	stmt, err := tx.Prepare(listerQuery)
	if err != nil {
		return handleError(listerQueryName, err)
	}

	for _, l := range processors.Listers {
		_, err := stmt.Exec(id, l)
		if err != nil {
			stmt.Close()
			return handleError(listerQueryName, err)
		}
	}

	if err := stmt.Close(); err != nil {
		return handleError(listerQueryName, err)
	}

	stmt, err = tx.Prepare(detectorQuery)
	if err != nil {
		return handleError(detectorQueryName, err)
	}

	for _, d := range processors.Detectors {
		_, err := stmt.Exec(id, d)
		if err != nil {
			stmt.Close()
			return handleError(detectorQueryName, err)
		}
	}

	if err := stmt.Close(); err != nil {
		return handleError(detectorQueryName, err)
	}

	return nil
}

func (tx *pgSession) findLayerNamespaces(layerID int64) ([]database.Namespace, error) {
	var namespaces []database.Namespace

	rows, err := tx.Query(searchLayerNamespaces, layerID)
	if err != nil {
		return nil, handleError("searchLayerFeatures", err)
	}

	for rows.Next() {
		ns := database.Namespace{}
		err := rows.Scan(&ns.Name, &ns.VersionFormat)
		if err != nil {
			return nil, err
		}
		namespaces = append(namespaces, ns)
	}
	return namespaces, nil
}

func (tx *pgSession) findLayerFeatures(layerID int64) ([]database.Feature, error) {
	var features []database.Feature

	rows, err := tx.Query(searchLayerFeatures, layerID)
	if err != nil {
		return nil, handleError("searchLayerFeatures", err)
	}

	for rows.Next() {
		f := database.Feature{}
		err := rows.Scan(&f.Name, &f.Version, &f.VersionFormat)
		if err != nil {
			return nil, err
		}
		features = append(features, f)
	}
	return features, nil
}

func (tx *pgSession) findLayer(hash string) (database.LayerMetadata, int64, bool, error) {
	var (
		layerID int64
		layer   = database.LayerMetadata{Hash: hash, ProcessedBy: database.Processors{}}
	)

	if hash == "" {
		return layer, layerID, false, commonerr.NewBadRequestError("Empty Layer Hash is not allowed")
	}

	err := tx.QueryRow(searchLayer, hash).Scan(&layerID)
	if err != nil {
		if err == sql.ErrNoRows {
			return layer, layerID, false, nil
		}
		return layer, layerID, false, err
	}

	layer.ProcessedBy, err = tx.findLayerProcessors(layerID)
	return layer, layerID, true, err
}

func (tx *pgSession) findLayerProcessors(id int64) (database.Processors, error) {
	var (
		err        error
		processors database.Processors
	)

	if processors.Detectors, err = tx.findProcessors(searchLayerDetectors, id); err != nil {
		return processors, handleError("searchLayerDetectors", err)
	}

	if processors.Listers, err = tx.findProcessors(searchLayerListers, id); err != nil {
		return processors, handleError("searchLayerListers", err)
	}

	return processors, nil
}
