package postgres

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/quay/zlog"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/label"

	clairerror "github.com/quay/clair/v4/clair-error"
)

var (
	deleteNotificationsCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "clair",
			Subsystem: "notifier",
			Name:      "deletenotifications_total",
			Help:      "Total number of database queries issued in the deleteNotifications method.",
		},
		[]string{"query"},
	)
	deleteNotificationsDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "clair",
			Subsystem: "notifier",
			Name:      "deletenotifications_duration_seconds",
			Help:      "The duration of all queries issued in the deleteNotifications method",
		},
		[]string{"query"},
	)
)

// deleteNotifications garbage collects notifications and their associated
// id and receipt rows
func deleteNotifications(ctx context.Context, pool *pgxpool.Pool, id uuid.UUID) error {
	ctx = baggage.ContextWithValues(ctx,
		label.String("component", "notifier/postgres/deleteNotifications"),
		label.Stringer("notification_id", id),
	)

	const (
		deleteNotificationID = `DELETE FROM notification WHERE id = $1`
		deleteNotifications  = `DELETE FROM notification_body WHERE notification_id = $1`
		deleteReceipt        = `DELETE FROM receipt WHERE notification_id = $1`
	)

	tx, err := pool.Begin(ctx)
	if err != nil {
		return clairerror.ErrDeleteNotification{id, err}
	}

	start := time.Now()
	tag, err := tx.Exec(ctx, deleteNotifications, id.String())
	if err != nil {
		return clairerror.ErrDeleteNotification{id, err}
	}
	deleteNotificationsCounter.WithLabelValues("deleteNotifications").Add(1)
	deleteNotificationsDuration.WithLabelValues("deleteNotifications").Observe(time.Since(start).Seconds())
	if tag.RowsAffected() <= 0 {
		zlog.Warn(ctx).Msg("no notification bodies deleted")
	}

	start = time.Now()
	tag, err = tx.Exec(ctx, deleteReceipt, id.String())
	if err != nil {
		return clairerror.ErrDeleteNotification{id, err}
	}
	deleteNotificationsCounter.WithLabelValues("deleteReceipt").Add(1)
	deleteNotificationsDuration.WithLabelValues("deleteReceipt").Observe(time.Since(start).Seconds())
	if tag.RowsAffected() <= 0 {
		zlog.Warn(ctx).Msg("no notification receipt deleted")
	}

	start = time.Now()
	tag, err = tx.Exec(ctx, deleteNotificationID, id.String())
	if err != nil {
		return clairerror.ErrDeleteNotification{id, err}
	}
	deleteNotificationsCounter.WithLabelValues("deleteNotificationID").Add(1)
	deleteNotificationsDuration.WithLabelValues("deleteNotificationID").Observe(time.Since(start).Seconds())
	if tag.RowsAffected() <= 0 {
		zlog.Warn(ctx).Msg("no notification id deleted")
	}

	err = tx.Commit(ctx)
	if err != nil {
		return clairerror.ErrDeleteNotification{id, err}
	}
	return nil
}
