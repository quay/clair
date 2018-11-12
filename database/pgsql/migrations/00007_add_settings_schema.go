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
	// This migration creates new schema for settings.
	RegisterMigration(migrate.Migration{
		ID: 7,
		Up: migrate.Queries([]string{
			`CREATE TABLE IF NOT EXISTS Settings (
        id SERIAL PRIMARY KEY,
        name VARCHAR(128) NOT NULL,
        value VARCHAR(128) NOT NULL,
        UNIQUE (name));`,
			`INSERT INTO Settings (id, name, value) VALUES (1, 'updater-schedule', '@midnight');`,
		}),
		Down: migrate.Queries([]string{
			`DROP TABLE IF EXISTS Settings CASCADE;`,
		}),
	})
}
