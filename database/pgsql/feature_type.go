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

package pgsql

import "github.com/coreos/clair/database"

const (
	selectAllFeatureTypes = `SELECT id, name FROM feature_type`
)

type featureTypes struct {
	byID   map[int]database.FeatureType
	byName map[database.FeatureType]int
}

func newFeatureTypes() *featureTypes {
	return &featureTypes{make(map[int]database.FeatureType), make(map[database.FeatureType]int)}
}

func (tx *pgSession) getFeatureTypeMap() (*featureTypes, error) {
	rows, err := tx.Query(selectAllFeatureTypes)
	if err != nil {
		return nil, err
	}

	types := newFeatureTypes()
	for rows.Next() {
		var (
			id   int
			name database.FeatureType
		)
		if err := rows.Scan(&id, &name); err != nil {
			return nil, err
		}

		types.byID[id] = name
		types.byName[name] = id
	}

	return types, nil
}
