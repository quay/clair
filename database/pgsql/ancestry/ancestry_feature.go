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

package ancestry

import (
	"database/sql"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/database/pgsql/detector"
	"github.com/coreos/clair/database/pgsql/feature"
	"github.com/coreos/clair/database/pgsql/util"
	"github.com/coreos/clair/pkg/commonerr"
)

const findAncestryFeatures = `
	SELECT namespace.name, namespace.version_format, feature.name, 
		feature.version, feature.version_format, feature_type.name, ancestry_layer.ancestry_index, 
		ancestry_feature.feature_detector_id, ancestry_feature.namespace_detector_id
	FROM namespace, feature, feature_type, namespaced_feature, ancestry_layer, ancestry_feature
	WHERE ancestry_layer.ancestry_id = $1
		AND feature_type.id = feature.type
		AND ancestry_feature.ancestry_layer_id = ancestry_layer.id
		AND ancestry_feature.namespaced_feature_id = namespaced_feature.id
		AND namespaced_feature.feature_id = feature.id
		AND namespaced_feature.namespace_id = namespace.id`

func FindAncestryFeatures(tx *sql.Tx, ancestryID int64, detectors detector.DetectorMap) (map[int64][]database.AncestryFeature, error) {
	// ancestry_index -> ancestry features
	featureMap := make(map[int64][]database.AncestryFeature)
	// retrieve ancestry layer's namespaced features
	rows, err := tx.Query(findAncestryFeatures, ancestryID)
	if err != nil {
		return nil, util.HandleError("findAncestryFeatures", err)
	}

	defer rows.Close()

	for rows.Next() {
		var (
			featureDetectorID   int64
			namespaceDetectorID sql.NullInt64
			feature             database.NamespacedFeature
			// index is used to determine which layer the feature belongs to.
			index sql.NullInt64
		)

		if err := rows.Scan(
			&feature.Namespace.Name,
			&feature.Namespace.VersionFormat,
			&feature.Feature.Name,
			&feature.Feature.Version,
			&feature.Feature.VersionFormat,
			&feature.Feature.Type,
			&index,
			&featureDetectorID,
			&namespaceDetectorID,
		); err != nil {
			return nil, util.HandleError("findAncestryFeatures", err)
		}

		if feature.Feature.VersionFormat != feature.Namespace.VersionFormat {
			// Feature must have the same version format as the associated
			// namespace version format.
			return nil, database.ErrInconsistent
		}

		fDetector, ok := detectors.ByID[featureDetectorID]
		if !ok {
			return nil, database.ErrInconsistent
		}

		var nsDetector database.Detector
		if !namespaceDetectorID.Valid {
			nsDetector = database.Detector{}
		} else {
			nsDetector, ok = detectors.ByID[namespaceDetectorID.Int64]
			if !ok {
				return nil, database.ErrInconsistent
			}
		}

		featureMap[index.Int64] = append(featureMap[index.Int64], database.AncestryFeature{
			NamespacedFeature: feature,
			FeatureBy:         fDetector,
			NamespaceBy:       nsDetector,
		})
	}

	return featureMap, nil
}

func InsertAncestryFeatures(tx *sql.Tx, ancestryLayerID int64, layer database.AncestryLayer) error {
	detectors, err := detector.FindAllDetectors(tx)
	if err != nil {
		return err
	}

	nsFeatureIDs, err := feature.FindNamespacedFeatureIDs(tx, layer.GetFeatures())
	if err != nil {
		return err
	}

	// find the detectors for each feature
	stmt, err := tx.Prepare(insertAncestryFeatures)
	if err != nil {
		return util.HandleError("insertAncestryFeatures", err)
	}

	defer stmt.Close()

	for index, id := range nsFeatureIDs {
		if !id.Valid {
			return database.ErrMissingEntities
		}

		var namespaceDetectorID sql.NullInt64
		var ok bool
		namespaceDetectorID.Int64, ok = detectors.ByValue[layer.Features[index].NamespaceBy]
		if ok {
			namespaceDetectorID.Valid = true
		}

		featureDetectorID, ok := detectors.ByValue[layer.Features[index].FeatureBy]
		if !ok {
			return database.ErrMissingEntities
		}

		if _, err := stmt.Exec(ancestryLayerID, id, featureDetectorID, namespaceDetectorID); err != nil {
			return util.HandleError("insertAncestryFeatures", commonerr.CombineErrors(err, stmt.Close()))
		}
	}

	return nil
}
