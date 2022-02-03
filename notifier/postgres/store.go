package postgres

import (
	"context"

	"github.com/jackc/pgconn"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
)

// Store implements the notifier.Store interface
type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool}
}

// As a rule of thumb, admin/worker locks should be in the two-part keyspace to
// avoid clashing with the manifest locks. They're engine wide, so it's a
// concern even here in the notifier's bailiwick.
const (
	adminKeyspace int32 = 4

	_ int32 = iota
	gcLock
)

func errLabel(e error) string {
	if e == nil {
		return `false`
	}
	return `true`
}

type statusMetrics struct {
	counter  *prometheus.CounterVec
	affected *prometheus.CounterVec
	dur      *prometheus.HistogramVec
}

// TxExec runs the passed query in the provided transaction, recording it as
// "name" with the metrics passed in "m".
//
// This is highly specific to how metrics are used in this package, and will
// panic if there are more than two labels unpopulated. It's expected that
// they're "query" and "error", respectively.
func txExec(ctx context.Context, m statusMetrics, tx pgx.Tx, name, query string, args []interface{}) error {
	var err error
	var tag pgconn.CommandTag
	timer := prometheus.NewTimer(prometheus.ObserverFunc(func(v float64) {
		m.dur.WithLabelValues(name, errLabel(err)).Observe(v)
	}))
	defer timer.ObserveDuration()
	tag, err = tx.Exec(ctx, query, args...)
	m.counter.WithLabelValues(name, errLabel(err)).Add(1)
	m.affected.WithLabelValues(name, errLabel(err)).Add(float64(tag.RowsAffected()))
	if err != nil {
		return err
	}
	return nil
}
