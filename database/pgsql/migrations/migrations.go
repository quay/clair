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

// Package migrations regroups every migrations available to the pgsql database
// backend.
package migrations

import "github.com/remind101/migrate"

// Migrations contains every available migrations.
var Migrations []migrate.Migration

// RegisterMigration adds the specified migration to the available migrations.
func RegisterMigration(migration migrate.Migration) {
	Migrations = append(Migrations, migration)
}
