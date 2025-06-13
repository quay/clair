package postgres

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/log/testingadapter"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/tracelog"
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
	tracer := &tracelog.TraceLog{
		LogLevel: tracelog.LogLevelInfo,
		Logger:   testingadapter.NewLogger(t),
	}
	if testing.Verbose() {
		tracer.LogLevel = tracelog.LogLevelError
	}
	cfg.ConnConfig.Tracer = tracer

	if err := Init(ctx, cfg.ConnConfig); err != nil {
		t.Fatalf("failed to init database: %v", err)
	}

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("failed to create connpool: %v", err)
	}
	t.Cleanup(pool.Close)
	return NewStore(pool)
}
