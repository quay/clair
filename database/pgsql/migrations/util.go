package migrations

import "github.com/remind101/migrate"

// MigrationQuery contains the Up migration and Down migration in Plain strings.
type MigrationQuery struct {
	Up   []string
	Down []string
}

// ConcatMigrationQueries concats migration queries in the give order.
func ConcatMigrationQueries(qs []MigrationQuery) MigrationQuery {
	r := MigrationQuery{}
	for _, q := range qs {
		r.Up = append(r.Up, q.Up...)
		r.Down = append(r.Down, q.Down...)
	}
	return r
}

// NewSimpleMigration returns a simple migration plan with all provided
// migration queries concatted in order.
func NewSimpleMigration(id int, qs []MigrationQuery) migrate.Migration {
	q := ConcatMigrationQueries(qs)
	return migrate.Migration{
		ID:   id,
		Up:   migrate.Queries(q.Up),
		Down: migrate.Queries(q.Down),
	}
}
