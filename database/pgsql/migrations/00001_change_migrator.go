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

import (
	"database/sql"

	"github.com/remind101/migrate"
)

func init() {
	// This migration removes the data maintained by the previous migration tool
	// (liamstask/goose), and if it was present, mark the 00002_initial_schema
	// migration as done.
	RegisterMigration(migrate.Migration{
		ID: 1,
		Up: func(tx *sql.Tx) error {
			// Verify that goose was in use before, otherwise skip this migration.
			var e bool
			err := tx.QueryRow("SELECT true FROM pg_class WHERE relname = $1", "goose_db_version").Scan(&e)
			if err == sql.ErrNoRows {
				return nil
			}
			if err != nil {
				return err
			}

			// Delete goose's data.
			_, err = tx.Exec("DROP TABLE goose_db_version CASCADE")
			if err != nil {
				return err
			}

			// Mark the '00002_initial_schema' as done.
			_, err = tx.Exec("INSERT INTO schema_migrations (version) VALUES (2)")

			return err
		},
		Down: migrate.Queries([]string{}),
	})
}
