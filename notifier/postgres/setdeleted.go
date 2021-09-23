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
	setDeletedCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "clair",
			Subsystem: "notifier",
			Name:      "setdeleted_total",
			Help:      "Total number of database queries issued in the setDeleted method.",
		},
		[]string{"query"},
	)
	setDeletedDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "clair",
			Subsystem: "notifier",
			Name:      "setdeleted_duration_seconds",
			Help:      "The duration of all queries issued in the setDeleted method",
		},
		[]string{"query"},
	)
)

// setDeleted will update the receipt's status to "deleted" for the provided
// notification id
func setDeleted(ctx context.Context, pool *pgxpool.Pool, id uuid.UUID) error {
	const (
		query = `UPDATE receipt SET status = 'deleted', ts = CURRENT_TIMESTAMP WHERE notification_id = $1`
	)

	start := time.Now()
	tag, err := pool.Exec(ctx, query, id.String())
	if err != nil {
		return clairerror.ErrReceipt{id, err}
	}
	setDeletedCounter.WithLabelValues("query").Add(1)
	setDeletedDuration.WithLabelValues("query").Observe(time.Since(start).Seconds())
	if tag.RowsAffected() <= 0 {
		return clairerror.ErrNoReceipt{id}
	}

	return nil
}
