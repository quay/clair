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

package feature

import (
	"database/sql"
	"fmt"
	"sort"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/database/pgsql/util"
	"github.com/coreos/clair/pkg/commonerr"
)

const (
	linkSourceToBinary = `WITH source_feature AS (
	SELECT id AS source_id FROM feature WHERE
         name = $1 AND version = $2 AND version_format = $3 AND type = $4
         ),

	binary_feature AS (
        SELECT id AS binary_id FROM feature WHERE 
		name = $5 AND version = $6 AND version_format = $7 AND type = $8
         )
	      
INSERT INTO source_binary_mapping (source_feature, binary_feature) VALUES 
          (
          	(SELECT source_id FROM source_feature),
          	(SELECT binary_id FROM binary_feature)
          )
          ON CONFLICT DO NOTHING;
		  `
)

func queryPersistFeature(count int) string {
	return util.QueryPersist(count,
		"feature",
		"feature_name_version_version_format_type_key",
		"name",
		"version",
		"version_format",
		"type")
}

func querySearchFeatureID(featureCount int) string {
	return fmt.Sprintf(`
		SELECT id, name, version, version_format, type
		FROM Feature WHERE (name, version, version_format, type) IN (%s)`,
		util.QueryString(4, featureCount),
	)
}

func PersistFeatures(tx *sql.Tx, features []database.Feature) error {
	if len(features) == 0 {
		return nil
	}

	types, err := GetFeatureTypeMap(tx)
	if err != nil {
		return err
	}

	for _, f := range features {
		if f.Source != nil {
			features = append(features, f)
		}
	}

	// Sorting is needed before inserting into database to prevent deadlock.
	sort.Slice(features, func(i, j int) bool {
		return features[i].Name < features[j].Name ||
			features[i].Version < features[j].Version ||
			features[i].VersionFormat < features[j].VersionFormat
	})

	// TODO(Sida): A better interface for bulk insertion is needed.
	keys := make([]interface{}, 0)
	for _, f := range features {
		keys = append(keys, f.Name, f.Version, f.VersionFormat, types.ByName[f.Type])
		if f.Name == "" || f.Version == "" || f.VersionFormat == "" {
			return commonerr.NewBadRequestError("Empty feature name, version or version format is not allowed")
		}
	}

	_, err = tx.Exec(queryPersistFeature(len(features)), keys...)
	if err != nil {
		return util.HandleError("queryPersistFeature", err)
	}

	for _, f := range features {
		if f.Source != nil {
			_, err := tx.Exec(linkSourceToBinary,
				f.Source.Name,
				f.Source.Version,
				f.Source.VersionFormat,
				types.ByName[f.Source.Type],
				f.Name,
				f.Version,
				f.VersionFormat,
				types.ByName[f.Type],
			)
			if err != nil {
				return util.HandleError("queryPersistFeature", err)
			}
		}
	}

	return nil
}

func FindFeatureIDs(tx *sql.Tx, fs []database.Feature) ([]sql.NullInt64, error) {
	if len(fs) == 0 {
		return nil, nil
	}

	types, err := GetFeatureTypeMap(tx)
	if err != nil {
		return nil, err
	}

	fMap := map[database.Feature]sql.NullInt64{}

	keys := make([]interface{}, 0, len(fs)*4)
	for _, f := range fs {
		typeID := types.ByName[f.Type]
		keys = append(keys, f.Name, f.Version, f.VersionFormat, typeID)
		fMap[f] = sql.NullInt64{}
	}

	rows, err := tx.Query(querySearchFeatureID(len(fs)), keys...)
	if err != nil {
		return nil, util.HandleError("querySearchFeatureID", err)
	}
	defer rows.Close()

	var (
		id sql.NullInt64
		f  database.Feature
	)
	for rows.Next() {
		var typeID int
		err := rows.Scan(&id, &f.Name, &f.Version, &f.VersionFormat, &typeID)
		if err != nil {
			return nil, util.HandleError("querySearchFeatureID", err)
		}

		f.Type = types.ByID[typeID]
		fMap[f] = id
	}

	ids := make([]sql.NullInt64, len(fs))
	for i, f := range fs {
		ids[i] = fMap[f]
	}

	return ids, nil
}
