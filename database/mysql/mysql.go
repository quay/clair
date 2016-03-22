// Copyright 2015 clair authors
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

// Package mysql implements database.Datastore with MySQL.
package mysql

import (
	"database/sql"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"runtime"
	"strings"

	"bitbucket.org/liamstask/goose/lib/goose"
	"github.com/coreos/clair/config"
	"github.com/coreos/clair/database"
	cerrors "github.com/coreos/clair/utils/errors"
	"github.com/coreos/pkg/capnslog"
	_ "github.com/go-sql-driver/mysql"
	"github.com/hashicorp/golang-lru"
	"github.com/pborman/uuid"
)

var (
	log = capnslog.NewPackageLogger("github.com/coreos/clair", "mysql")
)

const DATABASENAME = "clair"
const DEFAULTFLAG = "?charset=utf8&parseTime=True"
const DEFAULTSOURCE = DATABASENAME + DEFAULTFLAG

type Queryer interface {
	Query(query string, args ...interface{}) (*sql.Rows, error)
	QueryRow(query string, args ...interface{}) *sql.Row
	Exec(query string, args ...interface{}) (sql.Result, error)
}

type mySQL struct {
	*sql.DB
	cache *lru.ARCCache
}

func (mySQL *mySQL) Close() {
	mySQL.DB.Close()
}

func (mySQL *mySQL) Ping() bool {
	return mySQL.DB.Ping() == nil
}

// Open creates a Datastore backed by a PostgreSQL database.
// It will run immediately every necessary migration on the database.
func Open(config *config.DatabaseConfig) (database.Datastore, error) {
	source := config.Source
	if strings.HasPrefix(source, "mysql://") {
		source = strings.TrimPrefix(source, "mysql://")
	}
	config.Source = source + DEFAULTSOURCE
	// Create Database if not exists
	err := createDatabase(source, DATABASENAME)
	if err != nil {
		log.Error(err)
		return nil, database.ErrCantOpen
	}
	return open(config)
}

func open(config *config.DatabaseConfig) (database.Datastore, error) {
	// Run migrations.
	if err := migrate(config.Source); err != nil {
		log.Error(err)
		return nil, database.ErrCantOpen
	}

	// Open database.
	db, err := sql.Open("mysql", config.Source)
	if err != nil {
		log.Error(err)
		return nil, database.ErrCantOpen
	}

	// Initialize cache.
	// TODO(Quentin-M): Benchmark with a simple LRU Cache.
	var cache *lru.ARCCache
	if config.CacheSize > 0 {
		cache, _ = lru.NewARC(config.CacheSize)
	}

	return &mySQL{DB: db, cache: cache}, nil
}

// migrate runs all available migrations on a pgSQL database.
func migrate(dataSource string) error {
	log.Info("running database migrations")

	_, filename, _, _ := runtime.Caller(1)
	migrationDir := path.Join(path.Dir(filename), "/migrations/")
	conf := &goose.DBConf{
		MigrationsDir: migrationDir,
		Driver: goose.DBDriver{
			Name:    "mysql",
			OpenStr: dataSource,
			Import:  "github.com/go-sql-driver/mysql",
			Dialect: &goose.MySqlDialect{},
		},
	}

	// Determine the most recent revision available from the migrations folder.
	target, err := goose.GetMostRecentDBVersion(conf.MigrationsDir)
	if err != nil {
		return err
	}

	// Run migrations
	err = goose.RunMigrations(conf, conf.MigrationsDir, target)
	if err != nil {
		return err
	}

	log.Info("database migration ran successfully")
	return nil
}

// TODO:
// createDatabase creates a new database.
// The dataSource parameter should not contain a dbname.
func createDatabase(dataSource, databaseName string) error {
	// Open database.
	log.Info("Create database: ", databaseName)
	db, err := sql.Open("mysql", dataSource)
	if err != nil {
		return fmt.Errorf("could not open database (CreateDatabase): %v", err)
	}
	defer db.Close()

	// Create database.
	_, err = db.Exec("CREATE DATABASE IF NOT EXISTS " + databaseName + " DEFAULT CHARACTER SET utf8 COLLATE utf8_general_ci")
	if err != nil {
		return fmt.Errorf("could not create database: %v", err)
	}

	return nil
}

// dropDatabase drops an existing database.
// The dataSource parameter should not contain a dbname.
func dropDatabase(dataSource, databaseName string) error {
	// Open database.
	db, err := sql.Open("mysql", dataSource)
	if err != nil {
		return fmt.Errorf("could not open database (DropDatabase): %v", err)
	}
	defer db.Close()

	// Drop database.
	if _, err = db.Exec("DROP DATABASE " + databaseName); err != nil {
		return fmt.Errorf("could not drop database: %v", err)
	}

	return nil
}

// TODO
// pgSQLTest wraps pgSQL for testing purposes.
// Its Close() method drops the database.
type pgSQLTest struct {
	*mySQL
	dataSourceDefaultDatabase string
	dbName                    string
}

// OpenForTest creates a test Datastore backed by a new PostgreSQL database.
// It creates a new unique and prefixed ("test_") database.
// Using Close() will drop the database.
func OpenForTest(name string, withTestData bool) (*pgSQLTest, error) {
	// Define the PostgreSQL connection strings.
	dataSource := "root@tcp(127.0.0.1:3306)/"
	if dataSourceEnv := os.Getenv("CLAIR_TEST_MYSQL"); dataSourceEnv != "" {
		dataSource = dataSourceEnv
	}
	dbName := "test_" + strings.ToLower(name) + "_" + strings.Replace(uuid.New(), "-", "_", -1)
	dataSourceDefaultDatabase := dataSource
	dataSourceTestDatabase := dataSource + dbName + "?charset=utf8&parseTime=True"

	// Create database.
	if err := createDatabase(dataSourceDefaultDatabase, dbName); err != nil {
		log.Error(err)
		return nil, database.ErrCantOpen
	}

	// Open database.
	db, err := open(&config.DatabaseConfig{Source: dataSourceTestDatabase, CacheSize: 0})
	if err != nil {
		dropDatabase(dataSourceDefaultDatabase, dbName)
		log.Error(err)
		return nil, database.ErrCantOpen
	}
	// Load test data if specified.
	if withTestData {
		_, filename, _, _ := runtime.Caller(0)
		d, _ := ioutil.ReadFile(path.Join(path.Dir(filename)) + "/testdata/data.sql")
		queries := strings.Split(fmt.Sprintf("%s", d), ";")
		for _, q := range queries {
			_, err = db.(*mySQL).Exec(q)
			if err != nil {
				dropDatabase(dataSourceDefaultDatabase, dbName)
				log.Error(err)
				return nil, database.ErrCantOpen
			}
		}
	}

	return &pgSQLTest{
		mySQL: db.(*mySQL),
		dataSourceDefaultDatabase: dataSourceDefaultDatabase,
		dbName: dbName}, nil
}

func (pgSQL *pgSQLTest) Close() {
	pgSQL.DB.Close()
	dropDatabase(pgSQL.dataSourceDefaultDatabase, pgSQL.dbName)
}

// handleError logs an error with an extra description and masks the error if it's an SQL one.
// This ensures we never return plain SQL errors and leak anything.
func handleError(desc string, err error) error {
	if err == nil {
		return nil
	}

	if err == sql.ErrNoRows {
		return cerrors.ErrNotFound
	}

	log.Errorf("%s: %v", desc, err)
	database.PromErrorsTotal.WithLabelValues(desc).Inc()

	if err == sql.ErrTxDone || strings.HasPrefix(err.Error(), "sql:") {
		return database.ErrBackendException
	}

	return err
}

// isErrUniqueViolation determines is the given error is a duplicate entry error.
func isErrUniqueViolation(err error) bool {
	if strings.Contains(fmt.Sprintf("%v", err), "Error 1062") {
		return true
	}
	return false
}
