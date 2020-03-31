package postgres

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/log/testingadapter"
	"github.com/jackc/pgx/v4/pgxpool"
	_ "github.com/jackc/pgx/v4/stdlib" // Needed for sqlx.Open
	"github.com/jmoiron/sqlx"
	"github.com/quay/clair/v4/notifier/migrations"
	"github.com/quay/claircore/test/integration"
	"github.com/remind101/migrate"
)

const (
	// connection string for our local development. see docker-compose.yaml at root
	DefaultDSN = `host=localhost port=5432 user=clair dbname=clair sslmode=disable`
)

func TestStore(ctx context.Context, t testing.TB) (*sqlx.DB, *Store, func()) {
	if os.Getenv(integration.EnvPGConnString) == "" {
		os.Setenv(integration.EnvPGConnString, DefaultDSN)
	}

	db, err := integration.NewDB(ctx, t)
	if err != nil {
		t.Fatalf("unable to create test database: %v", err)
	}

	cfg := db.Config()
	cfg.ConnConfig.LogLevel = pgx.LogLevelError
	cfg.ConnConfig.Logger = testingadapter.NewLogger(t)
	// we are going to use pgx for more control over connection pool and
	// and a cleaner api around bulk inserts
	pool, err := pgxpool.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("failed to create connpool: %v", err)
	}

	dsn := fmt.Sprintf("host=%s port=%d database=%s user=%s", cfg.ConnConfig.Host, cfg.ConnConfig.Port, cfg.ConnConfig.Database, cfg.ConnConfig.User)
	sx, err := sqlx.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("failed to sqlx Open: %v", err)
	}
	t.Log(dsn)

	// run migrations
	migrator := migrate.NewPostgresMigrator(sx.DB)
	migrator.Table = migrations.MigrationTable
	err = migrator.Exec(migrate.Up, migrations.Migrations...)
	if err != nil {
		t.Fatalf("failed to perform migrations: %v", err)
	}

	s := NewStore(pool)
	return sx, s, func() {
		sx.Close()
		pool.Close()
		db.Close(ctx, t)
	}
}
