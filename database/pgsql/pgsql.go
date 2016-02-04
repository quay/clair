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

// Package pgsql implements database.Datastore with PostgreSQL.
package pgsql

import (
	"database/sql"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"runtime"
	"strings"
	"time"

	"bitbucket.org/liamstask/goose/lib/goose"
	"github.com/coreos/clair/config"
	"github.com/coreos/clair/database"
	"github.com/coreos/clair/utils"
	cerrors "github.com/coreos/clair/utils/errors"
	"github.com/coreos/pkg/capnslog"
	"github.com/hashicorp/golang-lru"
	"github.com/lib/pq"
	"github.com/pborman/uuid"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	log = capnslog.NewPackageLogger("github.com/coreos/clair", "pgsql")

	promErrorsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "clair_pgsql_errors_total",
		Help: "Number of errors that PostgreSQL requests generated.",
	}, []string{"request"})

	promCacheHitsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "clair_pgsql_cache_hits_total",
		Help: "Number of cache hits that the PostgreSQL backend did.",
	}, []string{"object"})

	promCacheQueriesTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "clair_pgsql_cache_queries_total",
		Help: "Number of cache queries that the PostgreSQL backend did.",
	}, []string{"object"})

	promQueryDurationMilliseconds = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "clair_pgsql_query_duration_milliseconds",
		Help: "Time it takes to execute the database query.",
	}, []string{"query", "subquery"})

	promConcurrentLockVAFV = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "clair_pgsql_concurrent_lock_vafv_total",
		Help: "Number of transactions trying to hold the exclusive Vulnerability_Affects_FeatureVersion lock.",
	})
)

func init() {
	prometheus.MustRegister(promErrorsTotal)
	prometheus.MustRegister(promCacheHitsTotal)
	prometheus.MustRegister(promCacheQueriesTotal)
	prometheus.MustRegister(promQueryDurationMilliseconds)
	prometheus.MustRegister(promConcurrentLockVAFV)
}

type Queryer interface {
	Query(query string, args ...interface{}) (*sql.Rows, error)
	QueryRow(query string, args ...interface{}) *sql.Row
}

type pgSQL struct {
	*sql.DB
	cache *lru.ARCCache
}

func (pgSQL *pgSQL) Close() {
	pgSQL.DB.Close()
}

func (pgSQL *pgSQL) Ping() bool {
	return pgSQL.DB.Ping() == nil
}

// Open creates a Datastore backed by a PostgreSQL database.
//
// It will run immediately every necessary migration on the database.
func Open(config *config.DatabaseConfig) (database.Datastore, error) {
	// Run migrations.
	if err := migrate(config.Source); err != nil {
		log.Error(err)
		return nil, database.ErrCantOpen
	}

	// Open database.
	db, err := sql.Open("postgres", config.Source)
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

	return &pgSQL{DB: db, cache: cache}, nil
}

// migrate runs all available migrations on a pgSQL database.
func migrate(dataSource string) error {
	log.Info("running database migrations")

	_, filename, _, _ := runtime.Caller(1)
	migrationDir := path.Join(path.Dir(filename), "/migrations/")
	conf := &goose.DBConf{
		MigrationsDir: migrationDir,
		Driver: goose.DBDriver{
			Name:    "postgres",
			OpenStr: dataSource,
			Import:  "github.com/lib/pq",
			Dialect: &goose.PostgresDialect{},
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

// createDatabase creates a new database.
// The dataSource parameter should not contain a dbname.
func createDatabase(dataSource, databaseName string) error {
	// Open database.
	db, err := sql.Open("postgres", dataSource)
	if err != nil {
		return fmt.Errorf("could not open database (CreateDatabase): %v", err)
	}
	defer db.Close()

	// Create database.
	_, err = db.Exec("CREATE DATABASE " + databaseName)
	if err != nil {
		return fmt.Errorf("could not create database: %v", err)
	}

	return nil
}

// dropDatabase drops an existing database.
// The dataSource parameter should not contain a dbname.
func dropDatabase(dataSource, databaseName string) error {
	// Open database.
	db, err := sql.Open("postgres", dataSource)
	if err != nil {
		return fmt.Errorf("could not open database (DropDatabase): %v", err)
	}
	defer db.Close()

	// Kill any opened connection.
	if _, err := db.Exec(`
    SELECT pg_terminate_backend(pg_stat_activity.pid)
    FROM pg_stat_activity
    WHERE pg_stat_activity.datname = $1
    AND pid <> pg_backend_pid()`, databaseName); err != nil {
		return fmt.Errorf("could not drop database: %v", err)
	}

	// Drop database.
	if _, err = db.Exec("DROP DATABASE " + databaseName); err != nil {
		return fmt.Errorf("could not drop database: %v", err)
	}

	return nil
}

// pgSQLTest wraps pgSQL for testing purposes.
// Its Close() method drops the database.
type pgSQLTest struct {
	*pgSQL
	dataSourceDefaultDatabase string
	dbName                    string
}

// OpenForTest creates a test Datastore backed by a new PostgreSQL database.
// It creates a new unique and prefixed ("test_") database.
// Using Close() will drop the database.
func OpenForTest(name string, withTestData bool) (*pgSQLTest, error) {
	// Define the PostgreSQL connection strings.
	dataSource := "host=127.0.0.1 sslmode=disable user=postgres dbname="
	if dataSourceEnv := os.Getenv("CLAIR_TEST_PGSQL"); dataSourceEnv != "" {
		dataSource = dataSourceEnv + " dbname="
	}
	dbName := "test_" + strings.ToLower(name) + "_" + strings.Replace(uuid.New(), "-", "_", -1)
	dataSourceDefaultDatabase := dataSource + "postgres"
	dataSourceTestDatabase := dataSource + dbName

	// Create database.
	if err := createDatabase(dataSourceDefaultDatabase, dbName); err != nil {
		log.Error(err)
		return nil, database.ErrCantOpen
	}

	// Open database.
	db, err := Open(&config.DatabaseConfig{Source: dataSourceTestDatabase, CacheSize: 0})
	if err != nil {
		dropDatabase(dataSourceDefaultDatabase, dbName)
		log.Error(err)
		return nil, database.ErrCantOpen
	}

	// Load test data if specified.
	if withTestData {
		_, filename, _, _ := runtime.Caller(0)
		d, _ := ioutil.ReadFile(path.Join(path.Dir(filename)) + "/testdata/data.sql")
		_, err = db.(*pgSQL).Exec(string(d))
		if err != nil {
			dropDatabase(dataSourceDefaultDatabase, dbName)
			log.Error(err)
			return nil, database.ErrCantOpen
		}
	}

	return &pgSQLTest{
		pgSQL: db.(*pgSQL),
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
	promErrorsTotal.WithLabelValues(desc).Inc()

	if _, o := err.(*pq.Error); o || err == sql.ErrTxDone || strings.HasPrefix(err.Error(), "sql:") {
		return database.ErrBackendException
	}

	return err
}

// isErrUniqueViolation determines is the given error is a unique contraint violation.
func isErrUniqueViolation(err error) bool {
	pqErr, ok := err.(*pq.Error)
	return ok && pqErr.Code == "23505"
}

func observeQueryTime(query, subquery string, start time.Time) {
	utils.PrometheusObserveTimeMilliseconds(promQueryDurationMilliseconds.WithLabelValues(query, subquery), start)
}
