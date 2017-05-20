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

package migrations

import "github.com/remind101/migrate"

func init() {
	RegisterMigration(migrate.Migration{
		ID: 7,
		Up: migrate.Queries([]string{
			`ALTER TABLE Namespace ALTER COLUMN version_format SET DATA TYPE varchar(256);`,
			`ALTER TABLE Layer ALTER COLUMN name SET DATA TYPE varchar(256);`,
		}),
		Down: migrate.Queries([]string{
			`ALTER TABLE Namespace ALTER COLUMN version_format SET DATA TYPE varchar(128);`,
			`ALTER TABLE Layer ALTER COLUMN name SET DATA TYPE varchar(128);`,
		}),
	})
}
