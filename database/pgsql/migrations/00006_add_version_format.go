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
		ID: 6,
		Up: migrate.Queries([]string{
			`ALTER TABLE Namespace ADD COLUMN version_format varchar(128);`,
			`UPDATE Namespace SET version_format = 'rpm' WHERE name LIKE 'rhel%' OR name LIKE 'centos%' OR name LIKE 'fedora%' OR name LIKE 'amzn%' OR name LIKE 'scientific%' OR name LIKE 'ol%' OR name LIKE 'oracle%';`,
			`UPDATE Namespace SET version_format = 'dpkg' WHERE version_format is NULL;`,
		}),
		Down: migrate.Queries([]string{
			`ALTER TABLE Namespace DROP COLUMN version_format;`,
		}),
	})
}
