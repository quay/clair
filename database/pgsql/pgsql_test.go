// Copyright 2020 clair authors
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

import (
	"database/sql"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCallsMigrateOnReadWriteDB(t *testing.T) {
	testDB := pgSQL{
		config: Config{
			ReadOnly: false,
		},
	}

	migrationCalled := false

	pgSQLMigrateFn = func(db *sql.DB) error {
		migrationCalled = true

		return nil
	}

	testDB.migrateDatabase()

	assert.True(t, migrationCalled)
}

func TestMigrateNotCalledOnReadOnlyDB(t *testing.T) {
	testDB := pgSQL{
		config: Config{
			ReadOnly: true,
		},
	}

	migrationCalled := false

	pgSQLMigrateFn = func(db *sql.DB) error {
		migrationCalled = true

		return nil
	}

	testDB.migrateDatabase()

	assert.False(t, migrationCalled)
}
