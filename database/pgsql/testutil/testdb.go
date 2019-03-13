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

package testutil

import (
	"database/sql"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/coreos/clair/database/pgsql/migrations"
	"github.com/coreos/clair/pkg/pagination"
	"github.com/remind101/migrate"
)

var TestPaginationKey = pagination.Must(pagination.NewKey())

var userDBCount = `SELECT count(datname) FROM pg_database WHERE datistemplate = FALSE AND datname != 'postgres';`

func CreateAndConnectTestDB(t *testing.T, testName string) (*sql.DB, func()) {
	uri := "postgres@127.0.0.1:5432"
	connectionTemplate := "postgresql://%s?sslmode=disable"
	if envURI := os.Getenv("CLAIR_TEST_PGSQL"); envURI != "" {
		uri = envURI
	}

	db, err := sql.Open("postgres", fmt.Sprintf(connectionTemplate, uri))
	if err != nil {
		panic(err)
	}

	testName = strings.ToLower(testName)
	dbName := fmt.Sprintf("test_%s_%s", testName, time.Now().UTC().Format("2006_01_02_15_04_05"))
	t.Logf("creating temporary database name = %s", dbName)
	_, err = db.Exec("CREATE DATABASE " + dbName)
	if err != nil {
		panic(err)
	}

	testDB, err := sql.Open("postgres", fmt.Sprintf(connectionTemplate, uri+"/"+dbName))
	if err != nil {
		panic(err)
	}

	return testDB, func() {
		cleanupTestDB(t, dbName, db, testDB)
	}
}

func cleanupTestDB(t *testing.T, name string, db, testDB *sql.DB) {
	t.Logf("cleaning up temporary database %s", name)
	if db == nil {
		panic("db is none")
	}

	if testDB == nil {
		panic("testDB is none")
	}

	defer db.Close()

	if err := testDB.Close(); err != nil {
		panic(err)
	}

	// Kill any opened connection.
	if _, err := db.Exec(`
		SELECT pg_terminate_backend(pg_stat_activity.pid)
		FROM pg_stat_activity
		WHERE pg_stat_activity.datname = $1
		AND pid <> pg_backend_pid()`, name); err != nil {
		panic(err)
	}

	if _, err := db.Exec(`DROP DATABASE ` + name); err != nil {
		panic(err)
	}

	// ensure the database is cleaned up
	var count int
	if err := db.QueryRow(userDBCount).Scan(&count); err != nil {
		panic(err)
	}
}

func CreateTestDB(t *testing.T, testName string) (*sql.DB, func()) {
	connection, cleanup := CreateAndConnectTestDB(t, testName)
	err := migrate.NewPostgresMigrator(connection).Exec(migrate.Up, migrations.Migrations...)
	if err != nil {
		panic(err)
	}

	return connection, cleanup
}

func CreateTestDBWithFixture(t *testing.T, testName string) (*sql.DB, func()) {
	connection, cleanup := CreateTestDB(t, testName)
	session, err := connection.Begin()
	if err != nil {
		panic(err)
	}

	defer session.Rollback()

	loadFixtures(session)
	if err = session.Commit(); err != nil {
		panic(err)
	}

	return connection, cleanup
}

func CreateTestTx(t *testing.T, testName string) (*sql.Tx, func()) {
	connection, cleanup := CreateTestDB(t, testName)
	session, err := connection.Begin()
	if session == nil {
		panic("session is none")
	}

	if err != nil {
		panic(err)
	}

	return session, func() {
		session.Rollback()
		cleanup()
	}
}

func CreateTestTxWithFixtures(t *testing.T, testName string) (*sql.Tx, func()) {
	tx, cleanup := CreateTestTx(t, testName)
	defer func() {
		// ensure to cleanup when loadFixtures failed
		if r := recover(); r != nil {
			cleanup()
		}
	}()

	loadFixtures(tx)
	return tx, cleanup
}

func loadFixtures(tx *sql.Tx) {
	_, filename, _, _ := runtime.Caller(0)
	fixturePath := filepath.Join(filepath.Dir(filename), "data.sql")
	d, err := ioutil.ReadFile(fixturePath)
	if err != nil {
		panic(err)
	}

	_, err = tx.Exec(string(d))
	if err != nil {
		panic(err)
	}
}

func OpenSessionForTest(t *testing.T, name string, loadFixture bool) (*sql.DB, *sql.Tx) {
	var db *sql.DB
	if loadFixture {
		db, _ = CreateTestDB(t, name)
	} else {
		db, _ = CreateTestDBWithFixture(t, name)
	}

	tx, err := db.Begin()
	if err != nil {
		panic(err)
	}

	return db, tx
}

func RestartTransaction(db *sql.DB, tx *sql.Tx, commit bool) *sql.Tx {
	if !commit {
		if err := tx.Rollback(); err != nil {
			panic(err)
		}
	} else {
		if err := tx.Commit(); err != nil {
			panic(err)
		}
	}

	tx, err := db.Begin()
	if err != nil {
		panic(err)
	}

	return tx
}
