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

package migrations_test

import (
	"testing"

	"github.com/coreos/clair/database/pgsql/migrations"
	"github.com/coreos/clair/database/pgsql/testutil"
	_ "github.com/lib/pq"
	"github.com/remind101/migrate"
	"github.com/stretchr/testify/require"
)

var userTableCount = `SELECT tablename FROM pg_catalog.pg_tables WHERE schemaname='public'`

func TestMigration(t *testing.T) {
	db, cleanup := testutil.CreateAndConnectTestDB(t, "TestMigration")
	defer cleanup()

	err := migrate.NewPostgresMigrator(db).Exec(migrate.Up, migrations.Migrations...)
	if err != nil {
		require.Nil(t, err, err.Error())
	}

	err = migrate.NewPostgresMigrator(db).Exec(migrate.Down, migrations.Migrations...)
	if err != nil {
		require.Nil(t, err, err.Error())
	}

	rows, err := db.Query(userTableCount)
	if err != nil {
		panic(err)
	}

	var (
		tables []string
		table  string
	)
	for rows.Next() {
		if err = rows.Scan(&table); err != nil {
			panic(err)
		}
		tables = append(tables, table)
	}

	require.True(t, len(tables) == 1 && tables[0] == "schema_migrations", "Only `schema_migrations` should be left")
}
