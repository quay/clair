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

package migrations

import "github.com/remind101/migrate"

// MigrationQuery contains the Up migration and Down migration in Plain strings.
type MigrationQuery struct {
	Up   []string
	Down []string
}

// ConcatMigrationQueries concats migration queries in the give order.
func ConcatMigrationQueries(qs []MigrationQuery) MigrationQuery {
	r := MigrationQuery{}
	for _, q := range qs {
		r.Up = append(r.Up, q.Up...)
		r.Down = append(r.Down, q.Down...)
	}
	return r
}

// NewSimpleMigration returns a simple migration plan with all provided
// migration queries concatted in order.
func NewSimpleMigration(id int, qs []MigrationQuery) migrate.Migration {
	q := ConcatMigrationQueries(qs)
	return migrate.Migration{
		ID:   id,
		Up:   migrate.Queries(q.Up),
		Down: migrate.Queries(q.Down),
	}
}
