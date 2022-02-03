package postgres

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/log/testingadapter"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/quay/claircore/test/integration"
)

func TestingStore(ctx context.Context, t testing.TB) *Store {
	db, err := integration.NewDB(ctx, t)
	if err != nil {
		t.Fatalf("unable to create test database: %v", err)
	}
	t.Cleanup(func() { db.Close(ctx, t) })

	cfg := db.Config()
	// This looks backwards, but means that failures get lots of output and
	// verbose output gets a moderate amount of output.
	cfg.ConnConfig.LogLevel = pgx.LogLevelInfo
	if testing.Verbose() {
		cfg.ConnConfig.LogLevel = pgx.LogLevelError
	}
	cfg.ConnConfig.Logger = testingadapter.NewLogger(t)

	if err := Init(ctx, cfg.ConnConfig); err != nil {
		t.Fatalf("failed to init database: %v", err)
	}

	pool, err := pgxpool.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("failed to create connpool: %v", err)
	}
	t.Cleanup(pool.Close)
	return NewStore(pool)
}
