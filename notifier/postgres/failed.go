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
	failedCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "clair",
			Subsystem: "notifier",
			Name:      "failed_total",
			Help:      "Total number of database queries issued in the failed method.",
		},
		[]string{"query"},
	)
	failedDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "clair",
			Subsystem: "notifier",
			Name:      "failed_duration_seconds",
			Help:      "The duration of all queries issued in the failed method",
		},
		[]string{"query"},
	)
)

// created will return all notification ids in "failed" status
func failed(ctx context.Context, pool *pgxpool.Pool) ([]uuid.UUID, error) {
	const (
		query = `SELECT notification_id FROM receipt WHERE status = 'delivery_failed'`
	)

	ids := make([]uuid.UUID, 0, 0)
	start := time.Now()
	rows, err := pool.Query(ctx, query)
	if err != nil {
		return nil, clairerror.ErrFailed{err}
	}
	failedCounter.WithLabelValues("query").Add(1)
	failedDuration.WithLabelValues("query").Observe(time.Since(start).Seconds())
	defer rows.Close()
	for rows.Next() {
		var id uuid.UUID
		err := rows.Scan(&id)
		if err != nil {
			return nil, clairerror.ErrFailed{err}
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, clairerror.ErrFailed{err}
	}

	return ids, nil
}
