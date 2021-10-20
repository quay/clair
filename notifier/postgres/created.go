package postgres

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	clairerror "github.com/quay/clair/v4/clair-error"
)

var (
	createdCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "clair",
			Subsystem: "notifier",
			Name:      "created_total",
			Help:      "Total number of database queries issued in the created method.",
		},
		[]string{"query"},
	)
	createdDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "clair",
			Subsystem: "notifier",
			Name:      "created_duration_seconds",
			Help:      "The duration of all queries issued in the created method",
		},
		[]string{"query"},
	)
)

// created will return all notification ids in "created" status
func created(ctx context.Context, pool *pgxpool.Pool) ([]uuid.UUID, error) {
	const (
		query = `SELECT notification_id FROM receipt WHERE status = 'created'`
	)

	ids := make([]uuid.UUID, 0, 0)
	start := time.Now()
	rows, err := pool.Query(ctx, query)
	if err != nil {
		return nil, clairerror.ErrCreated{err}
	}
	createdCounter.WithLabelValues("query").Add(1)
	createdDuration.WithLabelValues("query").Observe(time.Since(start).Seconds())
	defer rows.Close()
	for rows.Next() {
		var id uuid.UUID
		err := rows.Scan(&id)
		if err != nil {
			return nil, clairerror.ErrCreated{err}
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, clairerror.ErrCreated{err}
	}

	return ids, nil
}
