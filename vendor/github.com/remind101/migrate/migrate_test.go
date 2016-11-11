package migrate_test

import (
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
	"github.com/remind101/migrate"
	"github.com/stretchr/testify/assert"
)

const (
	Sqlite   = "sqlite3"
	Postgres = "postgres"
)

// A flag to determine what database to run the suite against.
var database = flag.String("test.database", Sqlite, "The name of the database to run against. (sqlite3, postgres).")

var testMigrations = []migrate.Migration{
	{
		ID: 1,
		Up: func(tx *sql.Tx) error {
			_, err := tx.Exec("CREATE TABLE people (id int)")
			return err
		},
		Down: func(tx *sql.Tx) error {
			_, err := tx.Exec("DROP TABLE people")
			return err
		},
	},
	{
		ID: 2,
		// For simple sql migrations, you can use the migrate.Queries
		// helper.
		Up: migrate.Queries([]string{
			"ALTER TABLE people ADD COLUMN first_name text",
		}),
		Down: func(tx *sql.Tx) error {
			// It's not possible to remove a column with
			// sqlite.
			_, err := tx.Exec("SELECT 1 FROM people")
			return err
		},
	},
}

func TestMigrate(t *testing.T) {
	db := newDB(t)
	defer db.Close()

	migrations := testMigrations[:]

	err := migrate.Exec(db, migrate.Up, migrations...)
	assert.NoError(t, err)
	assert.Equal(t, []int{1, 2}, appliedMigrations(t, db))
	assertSchema(t, `
people
CREATE TABLE people (id int, first_name text)
`, db)

	err = migrate.Exec(db, migrate.Down, migrations...)
	assert.NoError(t, err)
	assert.Equal(t, []int{}, appliedMigrations(t, db))
	assertSchema(t, ``, db)
}

func TestMigrate_Individual(t *testing.T) {
	db := newDB(t)
	defer db.Close()

	err := migrate.Exec(db, migrate.Up, testMigrations[0])
	assert.NoError(t, err)
	assert.Equal(t, []int{1}, appliedMigrations(t, db))
	assertSchema(t, `
people
CREATE TABLE people (id int)
`, db)

	err = migrate.Exec(db, migrate.Up, testMigrations[1])
	assert.NoError(t, err)
	assert.Equal(t, []int{1, 2}, appliedMigrations(t, db))
	assertSchema(t, `
people
CREATE TABLE people (id int, first_name text)
`, db)
}

func TestMigrate_AlreadyRan(t *testing.T) {
	db := newDB(t)
	defer db.Close()

	migration := testMigrations[0]

	err := migrate.Exec(db, migrate.Up, migration)
	assert.NoError(t, err)
	assert.Equal(t, []int{1}, appliedMigrations(t, db))
	assertSchema(t, `
people
CREATE TABLE people (id int)
`, db)

	err = migrate.Exec(db, migrate.Up, migration)
	assert.NoError(t, err)
	assert.Equal(t, []int{1}, appliedMigrations(t, db))
	assertSchema(t, `
people
CREATE TABLE people (id int)
`, db)
}

func TestMigrate_SingleTransactionMode_Rollback(t *testing.T) {
	db := newDB(t)
	defer db.Close()

	migrator := migrate.NewMigrator(db)
	migrator.TransactionMode = migrate.SingleTransaction

	migrations := []migrate.Migration{
		testMigrations[0],
		testMigrations[1],
		migrate.Migration{
			ID: 3,
			Up: func(tx *sql.Tx) error {
				return errors.New("Rollback")
			},
		},
	}

	err := migrator.Exec(migrate.Up, migrations...)
	assert.Error(t, err)
	assert.Equal(t, []int{}, appliedMigrations(t, db))
	assertSchema(t, ``, db)
}

func TestMigrate_SingleTransactionMode_Commit(t *testing.T) {
	db := newDB(t)
	defer db.Close()

	migrator := migrate.NewMigrator(db)
	migrator.TransactionMode = migrate.SingleTransaction

	err := migrator.Exec(migrate.Up, testMigrations...)
	assert.NoError(t, err)
	assert.Equal(t, []int{1, 2}, appliedMigrations(t, db))
	assertSchema(t, `
people
CREATE TABLE people (id int, first_name text)
`, db)
}

func TestMigrate_Order(t *testing.T) {
	db := newDB(t)
	defer db.Close()

	migrations := []migrate.Migration{
		testMigrations[1],
		testMigrations[0],
	}

	err := migrate.Exec(db, migrate.Up, migrations...)
	assert.NoError(t, err)
	assert.Equal(t, []int{1, 2}, appliedMigrations(t, db))
	assertSchema(t, `
people
CREATE TABLE people (id int, first_name text)
`, db)
}

func TestMigrate_Rollback(t *testing.T) {
	db := newDB(t)
	defer db.Close()

	migration := migrate.Migration{
		ID: 1,
		Up: func(tx *sql.Tx) error {
			// This should completely ok
			if _, err := tx.Exec("CREATE TABLE people (id int)"); err != nil {
				return err
			}
			// This should throw an error
			if _, err := tx.Exec("ALTER TABLE foo ADD COLUMN first_name text"); err != nil {
				return err
			}
			return nil
		},
	}

	err := migrate.Exec(db, migrate.Up, migration)
	assert.Error(t, err)
	assert.Equal(t, []int{}, appliedMigrations(t, db))
	// If the transaction wasn't rolled back, we'd see a people table.
	assertSchema(t, ``, db)
	assert.IsType(t, &migrate.MigrationError{}, err)
}

func TestMigrate_Locking(t *testing.T) {
	db := newDB(t)
	defer db.Close()

	migrator := migrate.NewMigrator(db)
	if *database == Postgres {
		migrator = migrate.NewPostgresMigrator(db)
	}

	err := migrator.Exec(migrate.Up, testMigrations...)
	assert.NoError(t, err)
	assertSchema(t, `
people
CREATE TABLE people (id int, first_name text)
`, db)
	assert.Equal(t, []int{1, 2}, appliedMigrations(t, db))

	var called int
	// Generates a migration that sends on the given channel when it starts.
	migration := migrate.Migration{
		ID: 3,
		Up: func(tx *sql.Tx) error {
			called++
			_, err := tx.Exec(`INSERT INTO people (id, first_name) VALUES (1, 'Eric')`)
			return err
		},
	}

	m1 := make(chan error)
	m2 := make(chan error)

	// Start two migrations in parallel.
	go func() {
		m1 <- migrator.Exec(migrate.Up, migration)
	}()
	go func() {
		m2 <- migrator.Exec(migrate.Up, migration)
	}()

	assert.Nil(t, <-m1)
	assert.Nil(t, <-m2)
	assert.Equal(t, 1, called)

	assertSchema(t, `
people
CREATE TABLE people (id int, first_name text)
`, db)
	assert.Equal(t, []int{1, 2, 3}, appliedMigrations(t, db))
}

func assertSchema(t testing.TB, expectedSchema string, db *sql.DB) {
	if *database == Sqlite {
		schema, err := sqliteSchema(db)
		if err != nil {
			t.Fatal(err)
		}

		assert.Equal(t, strings.TrimSpace(expectedSchema), schema)
	}
}

func sqliteSchema(db *sql.DB) (string, error) {
	var tables []string
	rows, err := db.Query(`SELECT name, sql FROM sqlite_master
WHERE type='table'
ORDER BY name;`)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	for rows.Next() {
		var name, sql string
		if err := rows.Scan(&name, &sql); err != nil {
			return "", err
		}
		if name == migrate.DefaultTable {
			continue
		}
		tables = append(tables, fmt.Sprintf("%s\n%s", name, sql))
	}
	return strings.Join(tables, "\n\n"), nil
}

func appliedMigrations(t testing.TB, db *sql.DB) []int {
	rows, err := db.Query("SELECT version FROM " + migrate.DefaultTable)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	ids := []int{}
	for rows.Next() {
		var id int
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}

	return ids
}

// factory methods to open a database connection to a type of database.
var databases = map[string]func() (*sql.DB, error){
	Postgres: func() (*sql.DB, error) {
		name := "migrate_test"

		command := func(name string, arg ...string) *exec.Cmd {
			cmd := exec.Command(name, arg...)
			cmd.Stderr = os.Stderr
			cmd.Stdout = os.Stdout
			return cmd
		}

		command("dropdb", name).Run()
		if err := command("createdb", name).Run(); err != nil {
			return nil, err
		}

		return sql.Open("postgres", fmt.Sprintf("postgres://localhost/%s?sslmode=disable", name))
	},
	Sqlite: func() (*sql.DB, error) {
		os.Remove("migrate_test.db")
		return sql.Open("sqlite3", "migrate_test.db?cache=shared&mode=wrc")
	},
}

func newDB(t testing.TB) *sql.DB {
	open, ok := databases[*database]
	if !ok {
		t.Fatal(fmt.Sprintf("Unknown database: %s", *database))
	}

	db, err := open()
	if err != nil {
		t.Fatal(err)
	}

	return db
}
