package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	clairerror "github.com/quay/clair/v4/clair-error"
	"github.com/quay/clair/v4/notifier"
)

var (
	receiptByUOIDCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "clair",
			Subsystem: "notifier",
			Name:      "receiptbyuoid_total",
			Help:      "Total number of database queries issued in the receiptByUOID method.",
		},
		[]string{"query"},
	)
	receiptByUOIDDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "clair",
			Subsystem: "notifier",
			Name:      "receiptbyuoid_duration_seconds",
			Help:      "The duration of all queries issued in the receiptByUOID method",
		},
		[]string{"query"},
	)
)

// receipt returns a receipt for a given update operation id
//
// if the receipt does not exist a ErrNoReceipt is returned
func receiptByUOID(ctx context.Context, pool *pgxpool.Pool, id uuid.UUID) (notifier.Receipt, error) {
	const (
		query = `SELECT uo_id, notification_id, status, ts FROM receipt WHERE uo_id  = $1`
	)

	var r notifier.Receipt
	start := time.Now()
	row := pool.QueryRow(ctx, query, id.String())
	err := row.Scan(
		&r.UOID,
		&r.NotificationID,
		&r.Status,
		&r.TS,
	)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return r, clairerror.ErrNoReceipt{id}
	case err != nil:
		return r, clairerror.ErrReceipt{id, err}
	}
	receiptByUOIDCounter.WithLabelValues("query").Add(1)
	receiptByUOIDDuration.WithLabelValues("query").Observe(time.Since(start).Seconds())

	return r, nil
}
