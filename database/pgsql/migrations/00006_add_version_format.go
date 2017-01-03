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
	"strings"

	"github.com/remind101/migrate"
)

func init() {
	RegisterMigration(migrate.Migration{
		ID: 6,
		Up: func(tx *sql.Tx) error {
			_, err := tx.Exec(`ALTER TABLE Namespace ADD COLUMN version_format varchar(128);`)
			if err != nil {
				return err
			}

			rows, err := tx.Query(`SELECT name FROM Namespace FOR UPDATE;`)
			if err != nil {
				return err
			}

			for rows.Next() {
				var nsName string
				err = rows.Scan(&nsName)
				if err != nil {
					return err
				}

				// Backfill rpm namespaces.
				if strings.HasPrefix(nsName, "rhel") ||
					strings.HasPrefix(nsName, "centos") ||
					strings.HasPrefix(nsName, "fedora") ||
					strings.HasPrefix(nsName, "amzn") ||
					strings.HasPrefix(nsName, "scientific") ||
					strings.HasPrefix(nsName, "ol") ||
					strings.HasPrefix(nsName, "oracle") {
					_, err := tx.Exec(`UPDATE Namespace SET version_format = 'rpm' WHERE name = ?;`, nsName)
					if err != nil {
						return err
					}
				} else {
					// Fallback to dpkg.
					_, err := tx.Exec(`UPDATE Namespace SET version_format = 'dpkg' WHERE name = ?;`, nsName)
					if err != nil {
						return err
					}
				}
			}

			return nil
		},
		Down: migrate.Queries([]string{
			`ALTER TABLE Namespace DROP COLUMN version_format;`,
		}),
	})
}
