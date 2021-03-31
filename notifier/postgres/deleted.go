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
	deletedCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "clair",
			Subsystem: "notifier",
			Name:      "deleted_total",
			Help:      "Total number of database queries issued in the deleted method.",
		},
		[]string{"query"},
	)
	deletedDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "clair",
			Subsystem: "notifier",
			Name:      "deleted_duration_seconds",
			Help:      "The duration of all queries issued in the deleted method",
		},
		[]string{"query"},
	)
)

// deleted will return all notification ids in "deleted" status
func deleted(ctx context.Context, pool *pgxpool.Pool) ([]uuid.UUID, error) {
	const (
		query = `SELECT notification_id FROM receipt WHERE status = 'deleted'`
	)

	ids := make([]uuid.UUID, 0, 0)
	start := time.Now()
	rows, err := pool.Query(ctx, query)
	if err != nil {
		return nil, clairerror.ErrCreated{err}
	}
	deletedCounter.WithLabelValues("query").Add(1)
	deletedDuration.WithLabelValues("query").Observe(time.Since(start).Seconds())
	defer rows.Close()
	for rows.Next() {
		var id uuid.UUID
		err := rows.Scan(&id)
		if err != nil {
			return nil, clairerror.ErrCreated{err}
		}
		ids = append(ids, id)
	}

	return ids, nil
}
