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
	setDeliveryFailedCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "clair",
			Subsystem: "notifier",
			Name:      "setdeliveryfailed_total",
			Help:      "Total number of database queries issued in the setDeliveryFailed method.",
		},
		[]string{"query"},
	)
	setDeliveryFailedDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "clair",
			Subsystem: "notifier",
			Name:      "setdeliveryfailed_duration_seconds",
			Help:      "The duration of all queries issued in the setDeliveryFailed method",
		},
		[]string{"query"},
	)
)

// setDeliveryFailed will update the receipt's status to "delivery_failed" for the provided
// notification id
func setDeliveryFailed(ctx context.Context, pool *pgxpool.Pool, id uuid.UUID) error {
	const (
		query = `UPDATE receipt SET status = 'delivery_failed', ts = CURRENT_TIMESTAMP WHERE notification_id = $1`
	)

	start := time.Now()
	tag, err := pool.Exec(ctx, query, id.String())
	if err != nil {
		return clairerror.ErrReceipt{id, err}
	}
	setDeliveryFailedCounter.WithLabelValues("query").Add(1)
	setDeliveryFailedDuration.WithLabelValues("query").Observe(time.Since(start).Seconds())
	if tag.RowsAffected() <= 0 {
		return clairerror.ErrNoReceipt{id}
	}

	return nil
}
