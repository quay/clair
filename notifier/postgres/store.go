package postgres

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgconn"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/quay/clair/v4/notifier"
)

// Store implements the notifier.Store interface
type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool}
}

// Notifications retrieves the list of notifications associated with a
// notification id
func (s *Store) Notifications(ctx context.Context, id uuid.UUID, page *notifier.Page) ([]notifier.Notification, notifier.Page, error) {
	return notifications(ctx, s.pool, id, page)
}

// PutNotifications persists the provided notifications and associates
// them with the provided notification id
//
// PutNotifications must update the latest update operation for the provided
// updater in such a way that UpdateOperation returns the the provided update
// operation id when queried with the updater name
//
// PutNotifications must create a Receipt with status created status on
// successful persistence of notifications in such a way that Receipter.Created()
// returns the persisted notification id.
func (s *Store) PutNotifications(ctx context.Context, opts notifier.PutOpts) error {
	return putNotifications(ctx, s.pool, opts)
}

// DeleteNotifications garbage collects all notifications associated
// with a notification id.
//
// Normally Receipter.SetDeleted will be issues first, however
// application logic may decide to gc notifications which have not been
// set deleted after some period of time, thus this condition should not
// be checked.
func (s *Store) DeleteNotifications(ctx context.Context, id uuid.UUID) error {
	return deleteNotifications(ctx, s.pool, id)
}

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
