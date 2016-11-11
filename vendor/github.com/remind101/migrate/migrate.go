// Package migrate provides a dead simple Go package for performing sql
// migrations using database/sql.
package migrate

import (
	"database/sql"
	"fmt"
	"hash/crc32"
	"sort"
	"sync"
)

type MigrationDirection int

const (
	Up MigrationDirection = iota
	Down
)

type TransactionMode int

const (
	// In this mode, each migration is run in it's own isolated transaction.
	// If a migration fails, only that migration will be rolled back.
	IndividualTransactions TransactionMode = iota

	// In this mode, all migrations are run inside a single transaction. If
	// one migration fails, all migrations are rolled back.
	SingleTransaction
)

// MigrationError is an error that gets returned when an individual migration
// fails.
type MigrationError struct {
	Migration

	// The underlying error.
	Err error
}

// Error implements the error interface.
func (e *MigrationError) Error() string {
	return fmt.Sprintf("migration %d failed: %v", e.ID, e.Err)
}

// The default table to store what migrations have been run.
const DefaultTable = "schema_migrations"

// Migration represents a sql migration that can be migrated up or down.
type Migration struct {
	// ID is a unique, numeric, identifier for this migration.
	ID int

	// Up is a function that gets called when this migration should go up.
	Up func(tx *sql.Tx) error

	// Down is a function that gets called when this migration should go
	// down.
	Down func(tx *sql.Tx) error
}

// byID implements the sort.Interface interface for sorting migrations by
// ID.
type byID []Migration

func (m byID) Len() int           { return len(m) }
func (m byID) Less(i, j int) bool { return m[i].ID < m[j].ID }
func (m byID) Swap(i, j int)      { m[i], m[j] = m[j], m[i] }

// Migrator performs migrations.
type Migrator struct {
	// Table is the table to store what migrations have been run. The zero
	// value is DefaultTable.
	Table string

	// Locker is a sync.Locker to use to ensure that only 1 process is
	// running migrations.
	sync.Locker

	// The TransactionMode to use. The zero value is IndividualTransactions,
	// which runs each migration in it's own transaction.
	TransactionMode TransactionMode

	db *sql.DB
}

// postgresLocker implements the sync.Locker interface using pg_advisory_lock.
type postgresLocker struct {
	key uint32
	db  *sql.DB
}

// NewPostgresLocker returns a new sync.Locker that obtains locks with
// pg_advisory_lock.
func newPostgresLocker(db *sql.DB) sync.Locker {
	key := crc32.ChecksumIEEE([]byte("migrations"))
	return &postgresLocker{
		key: key,
		db:  db,
	}
}

// Lock obtains the advisory lock.
func (l *postgresLocker) Lock() {
	l.do("lock")
}

// Unlock removes the advisory Lock
func (l *postgresLocker) Unlock() {
	l.do("unlock")
}

func (l *postgresLocker) do(m string) {
	_, err := l.db.Exec(fmt.Sprintf("SELECT pg_advisory_%s(%d)", m, l.key))
	if err != nil {
		panic(fmt.Sprintf("migrate: %v", err))
	}
}

// NewMigrator returns a new Migrator instance that will use the sql.DB to
// perform the migrations.
func NewMigrator(db *sql.DB) *Migrator {
	return &Migrator{
		db:     db,
		Locker: new(sync.Mutex),
	}
}

// NewPostgresMigrator returns a new Migrator instance that uses the underlying
// sql.DB connection to a postgres database to perform migrations. It will use
// Postgres's advisory locks to ensure that only 1 migration is run at a time.
func NewPostgresMigrator(db *sql.DB) *Migrator {
	m := NewMigrator(db)
	m.Locker = newPostgresLocker(db)
	return m
}

// Exec runs the migrations in the given direction.
func (m *Migrator) Exec(dir MigrationDirection, migrations ...Migration) error {
	m.Lock()
	defer m.Unlock()

	_, err := m.db.Exec(fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s (version integer primary key not null)", m.table()))
	if err != nil {
		return err
	}

	var tx *sql.Tx
	if m.TransactionMode == SingleTransaction {
		tx, err = m.db.Begin()
		if err != nil {
			return err
		}
	}

	for _, migration := range sortMigrations(dir, migrations) {
		if m.TransactionMode == IndividualTransactions {
			tx, err = m.db.Begin()
			if err != nil {
				return err
			}
		}

		if err := m.runMigration(tx, dir, migration); err != nil {
			tx.Rollback()
			return err
		}

		if m.TransactionMode == IndividualTransactions {
			if err := tx.Commit(); err != nil {
				return err
			}
		}
	}

	if m.TransactionMode == SingleTransaction {
		if err := tx.Commit(); err != nil {
			return err
		}
	}

	return nil
}

// runMigration runs the given Migration in the given direction using the given
// transaction. This function does not commit or rollback the transaction,
// that's the responsibility of the consumer dependending on whether an error
// gets returned.
func (m *Migrator) runMigration(tx *sql.Tx, dir MigrationDirection, migration Migration) error {
	shouldMigrate, err := m.shouldMigrate(tx, migration.ID, dir)
	if err != nil {
		return err
	}

	if !shouldMigrate {
		return nil
	}

	var migrate func(tx *sql.Tx) error
	switch dir {
	case Up:
		migrate = migration.Up
	default:
		migrate = migration.Down
	}

	if err := migrate(tx); err != nil {
		return &MigrationError{Migration: migration, Err: err}
	}

	var query string
	switch dir {
	case Up:
		// Yes. This is a sql injection vulnerability. This gets around
		// the different bindings for sqlite3/postgres.
		//
		// If you're running migrations from user input, you're doing
		// something wrong.
		query = fmt.Sprintf("INSERT INTO %s (version) VALUES (%d)", m.table(), migration.ID)
	default:
		query = fmt.Sprintf("DELETE FROM %s WHERE version = %d", m.table(), migration.ID)
	}

	_, err = tx.Exec(query)
	return err
}

func (m *Migrator) shouldMigrate(tx *sql.Tx, id int, dir MigrationDirection) (bool, error) {
	// Check if this migration has already ran
	var _id int
	err := tx.QueryRow(fmt.Sprintf("SELECT version FROM %s WHERE version = %d", m.table(), id)).Scan(&_id)
	if err != nil && err != sql.ErrNoRows {
		return false, err
	}

	switch dir {
	case Up:
		// If the migration doesn't exist, then we need to run it.
		return err == sql.ErrNoRows, nil
	default:
		// If the migration exists, then we need to remove it.
		return err != sql.ErrNoRows, nil
	}
}

// table returns the name of the table to use to track the migrations.
func (m *Migrator) table() string {
	if m.Table == "" {
		return DefaultTable
	}

	return m.Table
}

// Exec is a convenience method that runs the migrations against the default
// table.
func Exec(db *sql.DB, dir MigrationDirection, migrations ...Migration) error {
	return NewMigrator(db).Exec(dir, migrations...)
}

// Queries returns a func(tx *sql.Tx) error function that performs the given sql
// queries in multiple Exec calls.
func Queries(queries []string) func(*sql.Tx) error {
	return func(tx *sql.Tx) error {
		for _, query := range queries {
			if _, err := tx.Exec(query); err != nil {
				return err
			}
		}

		return nil
	}
}

// sortMigrations sorts the migrations by id.
//
// When the direction is "Up", the migrations will be sorted by ID ascending.
// When the direction is "Down", the migrations will be sorted by ID descending.
func sortMigrations(dir MigrationDirection, migrations []Migration) []Migration {
	var m byID
	for _, migration := range migrations {
		m = append(m, migration)
	}

	switch dir {
	case Up:
		sort.Sort(byID(m))
	default:
		sort.Sort(sort.Reverse(byID(m)))
	}

	return m
}
