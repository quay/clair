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

	"github.com/coreos/clair/database/pgsql/namespace"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/database/pgsql/detector"
	"github.com/coreos/clair/database/pgsql/feature"
	"github.com/coreos/clair/database/pgsql/util"
)

const findLayerFeatures = `
SELECT
	f.name, f.version, f.version_format, ft.name, lf.detector_id, ns.name, ns.version_format
FROM
	layer_feature AS lf
LEFT JOIN feature f on f.id = lf.feature_id
LEFT JOIN feature_type ft on ft.id = f.type
LEFT JOIN namespace ns ON ns.id = lf.namespace_id

WHERE lf.layer_id = $1`

func queryPersistLayerFeature(count int) string {
	return util.QueryPersist(count,
		"layer_feature",
		"layer_feature_layer_id_feature_id_namespace_id_key",
		"layer_id",
		"feature_id",
		"detector_id",
		"namespace_id")
}

// dbLayerFeature represents the layer_feature table
type dbLayerFeature struct {
	layerID     int64
	featureID   int64
	detectorID  int64
	namespaceID sql.NullInt64
}

func FindLayerFeatures(tx *sql.Tx, layerID int64, detectors detector.DetectorMap) ([]database.LayerFeature, error) {
	rows, err := tx.Query(findLayerFeatures, layerID)
	if err != nil {
		return nil, util.HandleError("findLayerFeatures", err)
	}
	defer rows.Close()

	features := []database.LayerFeature{}
	for rows.Next() {
		var (
			detectorID int64
			feature    database.LayerFeature
		)
		var namespaceName, namespaceVersion sql.NullString
		if err := rows.Scan(&feature.Name, &feature.Version, &feature.VersionFormat, &feature.Type, &detectorID, &namespaceName, &namespaceVersion); err != nil {
			return nil, util.HandleError("findLayerFeatures", err)
		}
		feature.PotentialNamespace.Name = namespaceName.String
		feature.PotentialNamespace.VersionFormat = namespaceVersion.String

		feature.By = detectors.ByID[detectorID]
		features = append(features, feature)
	}

	return features, nil
}

func PersistAllLayerFeatures(tx *sql.Tx, layerID int64, features []database.LayerFeature) error {
	detectorMap, err := detector.FindAllDetectors(tx)
	if err != nil {
		return err
	}
	var namespaces []database.Namespace
	for _, feature := range features {
		namespaces = append(namespaces, feature.PotentialNamespace)
	}
	nameSpaceIDs, _ := namespace.FindNamespaceIDs(tx, namespaces)
	featureNamespaceMap := map[database.Namespace]sql.NullInt64{}
	rawFeatures := make([]database.Feature, 0, len(features))
	for i, f := range features {
		rawFeatures = append(rawFeatures, f.Feature)
		if f.PotentialNamespace.Valid() {
			featureNamespaceMap[f.PotentialNamespace] = nameSpaceIDs[i]
		}
	}

	featureIDs, err := feature.FindFeatureIDs(tx, rawFeatures)
	if err != nil {
		return err
	}
	var namespaceID sql.NullInt64
	dbFeatures := make([]dbLayerFeature, 0, len(features))
	for i, f := range features {
		detectorID := detectorMap.ByValue[f.By]
		featureID := featureIDs[i].Int64
		if !featureIDs[i].Valid {
			return database.ErrMissingEntities
		}
		namespaceID = featureNamespaceMap[f.PotentialNamespace]

		dbFeatures = append(dbFeatures, dbLayerFeature{layerID, featureID, detectorID, namespaceID})
	}

	if err := PersistLayerFeatures(tx, dbFeatures); err != nil {
		return err
	}

	return nil
}

func PersistLayerFeatures(tx *sql.Tx, features []dbLayerFeature) error {
	if len(features) == 0 {
		return nil
	}

	sort.Slice(features, func(i, j int) bool {
		return features[i].featureID < features[j].featureID
	})
	keys := make([]interface{}, 0, len(features)*4)

	for _, f := range features {
		keys = append(keys, f.layerID, f.featureID, f.detectorID, f.namespaceID)
	}

	_, err := tx.Exec(queryPersistLayerFeature(len(features)), keys...)
	if err != nil {
		return util.HandleError("queryPersistLayerFeature", err)
	}
	return nil
}
