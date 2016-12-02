// Copyright 2016 clair authors
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

package migrations

import "github.com/remind101/migrate"

func init() {
	RegisterMigration(migrate.Migration{
		ID: 3,
		Up: migrate.Queries([]string{
			`CREATE UNIQUE INDEX namespace_name_key ON Namespace (name);`,
			`CREATE INDEX vulnerability_name_idx ON Vulnerability (name);`,
			`CREATE INDEX vulnerability_namespace_id_name_idx ON Vulnerability (namespace_id, name);`,
			`CREATE UNIQUE INDEX featureversion_feature_id_version_key ON FeatureVersion (feature_id, version);`,
		}),
		Down: migrate.Queries([]string{
			`DROP INDEX namespace_name_key;`,
			`DROP INDEX vulnerability_name_idx;`,
			`DROP INDEX vulnerability_namespace_id_name_idx;`,
			`DROP INDEX featureversion_feature_id_version_key;`,
		}),
	})
}
