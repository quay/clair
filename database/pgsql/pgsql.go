package pgsql

import (
	"database/sql"
	"fmt"
	"io/ioutil"
	"path"
	"runtime"
	"strconv"
	"strings"

	"bitbucket.org/liamstask/goose/lib/goose"
	"github.com/coreos/clair/config"
	"github.com/coreos/clair/database"
	"github.com/coreos/pkg/capnslog"
	"github.com/hashicorp/golang-lru"
	"github.com/lib/pq"
	"github.com/pborman/uuid"
)

var log = capnslog.NewPackageLogger("github.com/coreos/clair", "pgsql")

type pgSQL struct {
	*sql.DB
	cache *lru.ARCCache
}

func (pgSQL *pgSQL) Close() {
	pgSQL.DB.Close()
}

// Open creates a Datastore backed by a PostgreSQL database.
//
// It will run immediately every necessary migration on the database.
func Open(config *config.DatabaseConfig) (database.Datastore, error) {
	// Run migrations.
	if err := Migrate(config.Source); err != nil {
		return nil, fmt.Errorf("could not run database migration: %v", err)
	}

	// Open database.
	db, err := sql.Open("postgres", config.Source)
	if err != nil {
		return nil, fmt.Errorf("could not open database (Open): %v", err)
	}

	// Initialize cache.
	// TODO(Quentin-M): Benchmark with a simple LRU Cache.
	var cache *lru.ARCCache
	if config.CacheSize > 0 {
		cache, _ = lru.NewARC(config.CacheSize)
	}

	return &pgSQL{DB: db, cache: cache}, nil
}

// Migrate runs all available migrations on a pgSQL database.
func Migrate(dataSource string) error {
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

// CreateDatabase creates a new database.
// The dataSource parameter should not contain a dbname.
func CreateDatabase(dataSource, databaseName string) error {
	// Open database.
	db, err := sql.Open("postgres", dataSource)
	if err != nil {
		return fmt.Errorf("could not open database (CreateDatabase): %v", err)
	}
	defer db.Close()

	// Create database.
	_, err = db.Exec("CREATE DATABASE " + databaseName + ";")
	if err != nil {
		return fmt.Errorf("could not create database: %v", err)
	}

	return nil
}

// DropDatabase drops an existing database.
// The dataSource parameter should not contain a dbname.
func DropDatabase(dataSource, databaseName string) error {
	// Open database.
	db, err := sql.Open("postgres", dataSource)
	if err != nil {
		return fmt.Errorf("could not open database (DropDatabase): %v", err)
	}
	defer db.Close()

	// Drop database.
	_, err = db.Exec("DROP DATABASE " + databaseName + ";")
	if err != nil {
		return fmt.Errorf("could not create database: %v", err)
	}

	return nil
}

// pgSQLTest wraps pgSQL for testing purposes.
// Its Close() method drops the database.
type pgSQLTest struct {
	*pgSQL
	dataSource string
	dbName     string
}

func (pgSQL *pgSQLTest) Close() {
	pgSQL.DB.Close()
	DropDatabase(pgSQL.dataSource+"dbname=postgres", pgSQL.dbName)
}

// OpenForTest creates a test Datastore backed by a new PostgreSQL database.
// It creates a new unique and prefixed ("test_") database.
// Using Close() will drop the database.
func OpenForTest(name string, withTestData bool) (*pgSQLTest, error) {
	dataSource := "host=127.0.0.1 sslmode=disable "
	dbName := "test_" + strings.ToLower(name) + "_" + strings.Replace(uuid.New(), "-", "_", -1)

	// Create database.
	err := CreateDatabase(dataSource+"dbname=postgres", dbName)
	if err != nil {
		return nil, err
	}

	// Open database.
	db, err := Open(&config.DatabaseConfig{Source: dataSource + "dbname=" + dbName, CacheSize: 0})
	if err != nil {
		DropDatabase(dataSource, dbName)
		return nil, err
	}

	// Load test data if specified.
	if withTestData {
		_, filename, _, _ := runtime.Caller(0)
		d, _ := ioutil.ReadFile(path.Join(path.Dir(filename)) + "/testdata/data.sql")
		_, err = db.(*pgSQL).Exec(string(d))
		if err != nil {
			DropDatabase(dataSource, dbName)
			return nil, err
		}
	}

	return &pgSQLTest{pgSQL: db.(*pgSQL), dataSource: dataSource, dbName: dbName}, nil
}

// buildInputArray constructs a PostgreSQL input array from the specified integers.
// Useful to use the `= ANY($1::integer[])` syntax that let us use a IN clause while using
// a single placeholder.
func buildInputArray(ints []int) string {
	str := "{"
	for i := 0; i < len(ints)-1; i++ {
		str = str + strconv.Itoa(ints[i]) + ","
	}
	str = str + strconv.Itoa(ints[len(ints)-1]) + "}"
	return str
}

// isErrUniqueViolation determines is the given error is a unique contraint violation.
func isErrUniqueViolation(err error) bool {
	pqErr, ok := err.(*pq.Error)
	return ok && pqErr.Code == "23505"
}
