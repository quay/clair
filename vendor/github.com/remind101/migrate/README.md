# Migrate

[![Build Status](https://travis-ci.org/remind101/migrate.svg?branch=master)](https://travis-ci.org/remind101/migrate)

Migrate is a Go library for doing migrations. It's stupidly simple and gets out of your way.

## Features

* It's only dependency is `database/sql`.
* It supports any type of migration you want to run (e.g. raw sql, or Go code).
* It doesn't provide a command. It's designed to be embedded in projects and used exclusively as a library.

## Usage

```go
migrations := []migrate.Migration{
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

db, _ := sql.Open("sqlite3", ":memory:")
_ = migrate.Exec(db, migrate.Up, migrations...)
```

### Locking

All migrations are run in a transaction, but if you attempt to run a single long running migration concurrently, you could run into a deadlock. For Postgres connections, `migrate` can use [pg_advisory_lock](http://www.postgresql.org/docs/9.1/static/explicit-locking.html) to ensure that only 1 migration is run at a time.

To use this, simply instantiate a `Migrator` instance using `migrate.NewPostgresMigrator`:

```go
migrator := NewPostgresMigrator(db)
_ = migrator.Exec(migrate.Up, migrations...)
```
