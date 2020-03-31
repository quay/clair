package postgres

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v4/pgxpool"
	clairerror "github.com/quay/clair/v4/clair-error"
	"github.com/rs/zerolog"
)

// deleteNotifications garbage collects notifications and their associated
// id and receipt rows
func deleteNotifications(ctx context.Context, pool *pgxpool.Pool, id uuid.UUID) error {
	log := zerolog.Ctx(ctx).With().
		Str("component", "notifier/postgres/deleteNotification").
		Logger()

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
		log.Warn().Str("notification_id", id.String()).Msg("no notification bodies deleted")
	}

	tag, err = tx.Exec(ctx, deleteReceipt, id.String())
	if err != nil {
		return clairerror.ErrDeleteNotification{id, err}
	}
	if tag.RowsAffected() <= 0 {
		log.Warn().Str("notification_id", id.String()).Msg("no notification receipt deleted")
	}

	tag, err = tx.Exec(ctx, deleteNotificationID, id.String())
	if err != nil {
		return clairerror.ErrDeleteNotification{id, err}
	}
	if tag.RowsAffected() <= 0 {
		log.Warn().Str("notification_id", id.String()).Msg("no notification id deleted")
	}

	err = tx.Commit(ctx)
	if err != nil {
		return clairerror.ErrDeleteNotification{id, err}
	}
	return nil
}
