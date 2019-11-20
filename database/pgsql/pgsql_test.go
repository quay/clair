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
