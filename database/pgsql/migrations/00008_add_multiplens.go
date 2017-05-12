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
		ID: 8,
		Up: migrate.Queries([]string{
			// set on deletion, remove the corresponding rows in database
			`CREATE TABLE IF NOT EXISTS Layer_Namespace(
				id SERIAL PRIMARY KEY,
				layer_id INT REFERENCES Layer(id) ON DELETE CASCADE,		  
				namespace_id INT REFERENCES Namespace(id) ON DELETE CASCADE,
				unique(layer_id, namespace_id)
			);`,
			`CREATE INDEX ON Layer_Namespace (namespace_id);`,
			`CREATE INDEX ON Layer_Namespace (layer_id);`,
			// move the namespace_id to the table
			`INSERT INTO Layer_Namespace (layer_id, namespace_id) SELECT id, namespace_id FROM Layer;`,
			// alter the Layer table to remove the column
			`ALTER TABLE IF EXISTS Layer DROP namespace_id;`,
		}),
		Down: migrate.Queries([]string{
			`ALTER TABLE IF EXISTS Layer ADD namespace_id INT NULL REFERENCES Namespace;`,
			`CREATE INDEX ON Layer (namespace_id);`,
			`UPDATE IF EXISTS Layer SET namespace_id = (SELECT lns.namespace_id FROM Layer_Namespace lns WHERE Layer.id = lns.layer_id LIMIT 1);`,
			`DROP TABLE IF EXISTS Layer_Namespace;`,
		}),
	})
}
