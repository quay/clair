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
	"net/url"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"bitbucket.org/liamstask/goose/lib/goose"
	"github.com/coreos/pkg/capnslog"
	"github.com/hashicorp/golang-lru"
	"github.com/lib/pq"
	"github.com/prometheus/client_golang/prometheus"
	"gopkg.in/yaml.v2"

	"github.com/coreos/clair/config"
	"github.com/coreos/clair/database"
	"github.com/coreos/clair/utils"
	cerrors "github.com/coreos/clair/utils/errors"
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

	database.Register("pgsql", openDatabase)
}

type Queryer interface {
	Query(query string, args ...interface{}) (*sql.Rows, error)
	QueryRow(query string, args ...interface{}) *sql.Row
}

type pgSQL struct {
	*sql.DB
	cache  *lru.ARCCache
	config Config
}

// Close closes the database and destroys if ManageDatabaseLifecycle has been specified in
// the configuration.
func (pgSQL *pgSQL) Close() {
	if pgSQL.DB != nil {
		pgSQL.DB.Close()
	}

	if pgSQL.config.ManageDatabaseLifecycle {
		dbName, pgSourceURL, _ := parseConnectionString(pgSQL.config.Source)
		dropDatabase(pgSourceURL, dbName)
	}
}

// Ping verifies that the database is accessible.
func (pgSQL *pgSQL) Ping() bool {
	return pgSQL.DB.Ping() == nil
}

// Config is the configuration that is used by openDatabase.
type Config struct {
	Source    string
	CacheSize int

	ManageDatabaseLifecycle bool
	FixturePath             string
}

// openDatabase opens a PostgresSQL-backed Datastore using the given configuration.
// It immediately every necessary migrations. If ManageDatabaseLifecycle is specified,
// the database will be created first. If FixturePath is specified, every SQL queries that are
// present insides will be executed.
func openDatabase(registrableComponentConfig config.RegistrableComponentConfig) (database.Datastore, error) {
	var pg pgSQL
	var err error

	// Parse configuration.
	pg.config = Config{
		CacheSize: 16384,
	}
	bytes, err := yaml.Marshal(registrableComponentConfig.Options)
	if err != nil {
		return nil, fmt.Errorf("pgsql: could not load configuration: %v", err)
	}
	err = yaml.Unmarshal(bytes, &pg.config)
	if err != nil {
		return nil, fmt.Errorf("pgsql: could not load configuration: %v", err)
	}

	dbName, pgSourceURL, err := parseConnectionString(pg.config.Source)
	if err != nil {
		return nil, err
	}

	// Create database.
	if pg.config.ManageDatabaseLifecycle {
		log.Info("pgsql: creating database")
		if err := createDatabase(pgSourceURL, dbName); err != nil {
			return nil, err
		}
	}

	// Open database.
	pg.DB, err = sql.Open("postgres", pg.config.Source)
	if err != nil {
		pg.Close()
		return nil, fmt.Errorf("pgsql: could not open database: %v", err)
	}

	// Verify database state.
	if err := pg.DB.Ping(); err != nil {
		pg.Close()
		return nil, fmt.Errorf("pgsql: could not open database: %v", err)
	}

	// Run migrations.
	if err := migrate(pg.config.Source); err != nil {
		pg.Close()
		return nil, err
	}

	// Load fixture data.
	if pg.config.FixturePath != "" {
		log.Info("pgsql: loading fixtures")

		d, err := ioutil.ReadFile(pg.config.FixturePath)
		if err != nil {
			pg.Close()
			return nil, fmt.Errorf("pgsql: could not open fixture file: %v", err)
		}

		_, err = pg.DB.Exec(string(d))
		if err != nil {
			pg.Close()
			return nil, fmt.Errorf("pgsql: an error occured while importing fixtures: %v", err)
		}
	}

	// Initialize cache.
	// TODO(Quentin-M): Benchmark with a simple LRU Cache.
	if pg.config.CacheSize > 0 {
		pg.cache, _ = lru.NewARC(pg.config.CacheSize)
	}

	return &pg, nil
}

func parseConnectionString(source string) (dbName string, pgSourceURL string, err error) {
	if source == "" {
		return "", "", cerrors.NewBadRequestError("pgsql: no database connection string specified")
	}

	sourceURL, err := url.Parse(source)
	if err != nil {
		return "", "", cerrors.NewBadRequestError("pgsql: database connection string is not a valid URL")
	}

	dbName = strings.TrimPrefix(sourceURL.Path, "/")

	pgSource := *sourceURL
	pgSource.Path = "/postgres"
	pgSourceURL = pgSource.String()

	return
}

// migrate runs all available migrations on a pgSQL database.
func migrate(source string) error {
	log.Info("running database migrations")

	_, filename, _, _ := runtime.Caller(1)
	migrationDir := filepath.Join(filepath.Dir(filename), "/migrations/")
	conf := &goose.DBConf{
		MigrationsDir: migrationDir,
		Driver: goose.DBDriver{
			Name:    "postgres",
			OpenStr: source,
			Import:  "github.com/lib/pq",
			Dialect: &goose.PostgresDialect{},
		},
	}

	// Determine the most recent revision available from the migrations folder.
	target, err := goose.GetMostRecentDBVersion(conf.MigrationsDir)
	if err != nil {
		return fmt.Errorf("pgsql: could not get most recent migration: %v", err)
	}

	// Run migrations.
	err = goose.RunMigrations(conf, conf.MigrationsDir, target)
	if err != nil {
		return fmt.Errorf("pgsql: an error occured while running migrations: %v", err)
	}

	log.Info("database migration ran successfully")
	return nil
}

// createDatabase creates a new database.
// The source parameter should not contain a dbname.
func createDatabase(source, dbName string) error {
	// Open database.
	db, err := sql.Open("postgres", source)
	if err != nil {
		return fmt.Errorf("pgsql: could not open 'postgres' database for creation: %v", err)
	}
	defer db.Close()

	// Create database.
	_, err = db.Exec("CREATE DATABASE " + dbName)
	if err != nil {
		return fmt.Errorf("pgsql: could not create database: %v", err)
	}

	return nil
}

// dropDatabase drops an existing database.
// The source parameter should not contain a dbname.
func dropDatabase(source, dbName string) error {
	// Open database.
	db, err := sql.Open("postgres", source)
	if err != nil {
		return fmt.Errorf("could not open database (DropDatabase): %v", err)
	}
	defer db.Close()

	// Kill any opened connection.
	if _, err = db.Exec(`
    SELECT pg_terminate_backend(pg_stat_activity.pid)
    FROM pg_stat_activity
    WHERE pg_stat_activity.datname = $1
    AND pid <> pg_backend_pid()`, dbName); err != nil {
		return fmt.Errorf("could not drop database: %v", err)
	}

	// Drop database.
	if _, err = db.Exec("DROP DATABASE " + dbName); err != nil {
		return fmt.Errorf("could not drop database: %v", err)
	}

	return nil
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
