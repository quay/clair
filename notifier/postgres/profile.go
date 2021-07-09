package postgres

import (
	"context"
	"runtime/pprof"

	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
)

// ConnectionProfile is the name of a profile for recording database
// connections.
const ConnectionProfile = `clair/notifier/postgres.conn`

var connProf = pprof.NewProfile(ConnectionProfile)

func ProfileSetup(cfg *pgxpool.Config) {
	if prev := cfg.BeforeAcquire; prev == nil {
		cfg.BeforeAcquire = defaultBA
	} else {
		cfg.BeforeAcquire = func(ctx context.Context, c *pgx.Conn) bool {
			connProf.Add(c, 3)
			return prev(ctx, c)
		}
	}
	if prev := cfg.AfterRelease; prev == nil {
		cfg.AfterRelease = defaultAR
	} else {
		cfg.AfterRelease = func(c *pgx.Conn) bool {
			connProf.Remove(c)
			return prev(c)
		}
	}
}
func defaultBA(_ context.Context, c *pgx.Conn) bool {
	connProf.Add(c, 3)
	return true
}
func defaultAR(c *pgx.Conn) bool {
	connProf.Remove(c)
	return true
}
