package config

import (
	"fmt"
	"net/url"
	"os"
	"strings"
)

// CheckConnString reports a warning for using the "connstring" member instead
// of the "database" member.
//
// This will panic if the type parameter is not [Matcher], [Indexer], or [Notifier].
func checkConnString[T any](ws *[]Warning, v *T) {
	var cs *string
	var d *Database
	switch v := any(v).(type) {
	case *Matcher:
		cs = &v.ConnString
		d = v.Database
	case *Indexer:
		cs = &v.ConnString
		d = v.Database
	case *Notifier:
		cs = &v.ConnString
		d = v.Database
	default:
		panic(fmt.Sprintf("programmer error: passed unexpected type: %T", v))
	}
	if *cs != "" {
		*ws = append(*ws, errConnString)
	}
	if d == nil {
		*ws = append(*ws, Warning{
			path: ".database",
			msg:  `missing database configuration`,
		})
	}
}

// ErrConnString is reported by [checkConnString] if the "connstring" member is in use.
var errConnString = Warning{
	path:  ".connstring",
	inner: fmt.Errorf(`using bare-string for database configuration deprecated: %w`, ErrDeprecated),
}

// SetConnString adjusts the passed variable by porting from the "connstring"
// member if necessary.
//
// This will panic if the type parameter is not [Matcher], [Indexer], or [Notifier].
func setConnString[T any](ws *[]Warning, v *T) {
	var cs *string
	var d *Database
	var m *bool
	switch v := any(v).(type) {
	case *Matcher:
		cs = &v.ConnString
		d = v.Database
		m = v.Migrations
	case *Indexer:
		cs = &v.ConnString
		d = v.Database
		m = v.Migrations
	case *Notifier:
		cs = &v.ConnString
		d = v.Database
		m = v.Migrations
	default:
		panic(fmt.Sprintf("programmer error: passed unexpected type: %T", v))
	}
	switch {
	case *cs != "" && d != nil:
		*cs = ""
	case *cs != "" && d == nil:
		d = &Database{
			Name:       `postgresql`,
			PostgreSQL: &DatabasePostgreSQL{DSN: *cs},
			Migrations: m,
		}
		*cs = ""
	case *cs == "" && d != nil: // OK, use as-is.
	case *cs == "" && d == nil: // Will probably explode later.
	}
}

// CheckPostgresqlDSN is a (very) light check that the value provided isn't completely bogus.
//
// Implementing more rigorous checks would be much more complicated.
// That's not to say it'd be an unwelcome addition, just that it's very large and probably not needed.
func checkPostgresqlDSN(s string) (w []Warning) {
	switch {
	case s == "":
		// Nothing specified, make sure something's in the environment.
		envSet := false
		for _, k := range os.Environ() {
			if strings.HasPrefix(k, `PG`) {
				envSet = true
				break
			}
		}
		if !envSet {
			w = append(w, Warning{
				msg: "connection string is empty and no relevant environment variables found",
			})
		}
	case strings.HasPrefix(s, "postgresql://"):
		// Looks like a URL
		if _, err := url.Parse(s); err != nil {
			w = append(w, Warning{inner: err})
		}
	case strings.Contains(s, `://`):
		w = append(w, Warning{
			msg: "connection string looks like a URL but scheme is unrecognized",
		})
	case strings.ContainsRune(s, '='):
		// Looks like a DSN
	default:
		w = append(w, Warning{
			msg: "unable to make sense of connection string",
		})
	}
	return w
}

// Database indicates the database configuration.
type Database struct {
	// Name indicates which database backend to use.
	//
	// This value must match the json/yaml tag.
	Name string `json:"name" yaml:"name"`
	// Migrations indicates if database migrations should run automatically.
	Migrations *bool `json:"migrations,omitempty" yaml:"migrations,omitempty"`
	// PostgreSQL is the PostgreSQL configuration.
	PostgreSQL *DatabasePostgreSQL `json:"postgresql,omitempty" yaml:"postgresql,omitempty"`
}

func (d *Database) lint() (ws []Warning, err error) {
	switch n := d.Name; n {
	case "postgresql": // OK
	case "postgres":
		ws = append(ws, Warning{
			msg:  fmt.Sprintf("unknown database: %q (did you mean %q?)", n, "postgresql"),
			path: ".name",
		})
	default:
		ws = append(ws, Warning{
			msg:  fmt.Sprintf("unknown database: %q", n),
			path: ".name",
		})
	}
	return ws, nil
}
func (d *Database) validate(_ Mode) ([]Warning, error) {
	return d.lint()
}

// DatabasePostgreSQL is the PostgreSQL-specific database configuration.
//
// Validation assumes that if the "DSN" member is empty but any environment variables with a "PG" prefix are present,
// the configuration is specified in via environment variables.
// This package implements no checking for the specifics of the DSN/URL/environment variables;
// providing malformed values will fail at the point of use instead of configuration validation.
type DatabasePostgreSQL struct {
	// DSN is a data source name (aka "connection string") as documented for [libpq], with the extensions supported by [pgxpool].
	//
	// [libpq]: https://www.postgresql.org/docs/current/libpq-connect.html#LIBPQ-CONNSTRING
	// [pgxpool]: https://pkg.go.dev/github.com/jackc/pgx/v4/pgxpool#ParseConfig
	DSN string `json:"dsn" yaml:"dsn"`
}

func (d *DatabasePostgreSQL) lint() ([]Warning, error) {
	return checkPostgresqlDSN(d.DSN), nil
}
func (d *DatabasePostgreSQL) validate(_ Mode) ([]Warning, error) {
	return d.lint()
}
