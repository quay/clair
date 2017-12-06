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

func (tx *pgSession) FindLayer(hash string) (database.Layer, database.Processors, bool, error) {
	l, p, _, ok, err := tx.findLayer(hash)
	return l, p, ok, err
}

func (tx *pgSession) FindLayerWithContent(hash string) (database.LayerWithContent, bool, error) {
	var (
		layer   database.LayerWithContent
		layerID int64
		ok      bool
		err     error
	)

	layer.Layer, layer.ProcessedBy, layerID, ok, err = tx.findLayer(hash)
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

func (tx *pgSession) PersistLayer(layer database.Layer) error {
	if layer.Hash == "" {
		return commonerr.NewBadRequestError("Empty Layer Hash is not allowed")
	}

	_, err := tx.Exec(queryPersistLayer(1), layer.Hash)
	if err != nil {
		return handleError("queryPersistLayer", err)
	}

	return nil
}

// PersistLayerContent relates layer identified by hash with namespaces,
// features and processors provided. If the layer, namespaces, features are not
// in database, the function returns an error.
func (tx *pgSession) PersistLayerContent(hash string, namespaces []database.Namespace, features []database.Feature, processedBy database.Processors) error {
	if hash == "" {
		return commonerr.NewBadRequestError("Empty layer hash is not allowed")
	}

	var layerID int64
	err := tx.QueryRow(searchLayer, hash).Scan(&layerID)
	if err != nil {
		return err
	}

	if err = tx.persistLayerNamespace(layerID, namespaces); err != nil {
		return err
	}

	if err = tx.persistLayerFeatures(layerID, features); err != nil {
		return err
	}

	if err = tx.persistLayerDetectors(layerID, processedBy.Detectors); err != nil {
		return err
	}

	if err = tx.persistLayerListers(layerID, processedBy.Listers); err != nil {
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

func (tx *pgSession) findLayer(hash string) (database.Layer, database.Processors, int64, bool, error) {
	var (
		layerID    int64
		layer      = database.Layer{Hash: hash}
		processors database.Processors
	)

	if hash == "" {
		return layer, processors, layerID, false, commonerr.NewBadRequestError("Empty Layer Hash is not allowed")
	}

	err := tx.QueryRow(searchLayer, hash).Scan(&layerID)
	if err != nil {
		if err == sql.ErrNoRows {
			return layer, processors, layerID, false, nil
		}
		return layer, processors, layerID, false, err
	}

	processors.Detectors, err = tx.findProcessors(searchLayerDetectors, "searchLayerDetectors", "detector", layerID)
	if err != nil {
		return layer, processors, layerID, false, err
	}

	processors.Listers, err = tx.findProcessors(searchLayerListers, "searchLayerListers", "lister", layerID)
	if err != nil {
		return layer, processors, layerID, false, err
	}

	return layer, processors, layerID, true, nil
}
