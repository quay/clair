// Copyright 2019 clair authors
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

package layer

import (
	"database/sql"
	"sort"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/database/pgsql/detector"
	"github.com/coreos/clair/database/pgsql/namespace"
	"github.com/coreos/clair/database/pgsql/util"
)

const findLayerNamespaces = `
SELECT ns.name, ns.version_format, ln.detector_id
	FROM layer_namespace AS ln, namespace AS ns
	WHERE ln.namespace_id = ns.id
		AND ln.layer_id = $1`

func queryPersistLayerNamespace(count int) string {
	return util.QueryPersist(count,
		"layer_namespace",
		"layer_namespace_layer_id_namespace_id_key",
		"layer_id",
		"namespace_id",
		"detector_id")
}

// dbLayerNamespace represents the layer_namespace table.
type dbLayerNamespace struct {
	layerID     int64
	namespaceID int64
	detectorID  int64
}

func FindLayerNamespaces(tx *sql.Tx, layerID int64, detectors detector.DetectorMap) ([]database.LayerNamespace, error) {
	rows, err := tx.Query(findLayerNamespaces, layerID)
	if err != nil {
		return nil, util.HandleError("findLayerNamespaces", err)
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

		namespace.By = detectors.ByID[detectorID]
		namespaces = append(namespaces, namespace)
	}

	return namespaces, nil
}

func PersistAllLayerNamespaces(tx *sql.Tx, layerID int64, namespaces []database.LayerNamespace) error {
	detectorMap, err := detector.FindAllDetectors(tx)
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

	rawNamespaceIDs, err := namespace.FindNamespaceIDs(tx, rawNamespaces)
	if err != nil {
		return err
	}

	dbLayerNamespaces := make([]dbLayerNamespace, 0, len(namespaces))
	for i, ns := range namespaces {
		detectorID := detectorMap.ByValue[ns.By]
		namespaceID := rawNamespaceIDs[i].Int64
		if !rawNamespaceIDs[i].Valid {
			return database.ErrMissingEntities
		}

		dbLayerNamespaces = append(dbLayerNamespaces, dbLayerNamespace{layerID, namespaceID, detectorID})
	}

	return PersistLayerNamespaces(tx, dbLayerNamespaces)
}

func PersistLayerNamespaces(tx *sql.Tx, namespaces []dbLayerNamespace) error {
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
		return util.HandleError("queryPersistLayerNamespace", err)
	}

	return nil
}
