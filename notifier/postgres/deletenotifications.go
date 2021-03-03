package postgres

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/quay/zlog"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/label"

	clairerror "github.com/quay/clair/v4/clair-error"
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

	tag, err := tx.Exec(ctx, deleteNotifications, id.String())
	if err != nil {
		return clairerror.ErrDeleteNotification{id, err}
	}
	if tag.RowsAffected() <= 0 {
		zlog.Warn(ctx).Msg("no notification bodies deleted")
	}

	tag, err = tx.Exec(ctx, deleteReceipt, id.String())
	if err != nil {
		return clairerror.ErrDeleteNotification{id, err}
	}
	if tag.RowsAffected() <= 0 {
		zlog.Warn(ctx).Msg("no notification receipt deleted")
	}

	tag, err = tx.Exec(ctx, deleteNotificationID, id.String())
	if err != nil {
		return clairerror.ErrDeleteNotification{id, err}
	}
	if tag.RowsAffected() <= 0 {
		zlog.Warn(ctx).Msg("no notification id deleted")
	}

	err = tx.Commit(ctx)
	if err != nil {
		return clairerror.ErrDeleteNotification{id, err}
	}
	return nil
}
