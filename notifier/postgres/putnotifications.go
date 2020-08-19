package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v4/pgxpool"
	clairerror "github.com/quay/clair/v4/clair-error"
	"github.com/quay/clair/v4/notifier"
	"github.com/quay/claircore/pkg/microbatch"
)

const (
	batchSize = 200
	batchTO   = 10 * time.Second
)

type notificationJSONB notifier.Notification

// putNotifications inserts the provided notifications, updates the latest seen update
// operation for the provide updater, and creates a receipt in created status for the
// notifiation id.
//
// these operations occur under a transcation to preserve an atomic operation.
func putNotifications(ctx context.Context, pool *pgxpool.Pool, opts notifier.PutOpts) error {
	const (
		insertNotification    = `INSERT INTO notification (id) VALUES ($1);`
		insertNotifcationBody = `INSERT INTO notification_body (id, notification_id, body) VALUES ($1, $2, $3);`
		insertReceipt         = `INSERT INTO receipt (notification_id, uo_id, status, ts) VALUES ($1, $2, 'created', CURRENT_TIMESTAMP);`
		insertUpdateOperation = `
		INSERT INTO notifier_update_operation (updater, uo_id, ts)
		VALUES ($1, $2, $3)
		`
	)
	tx, err := pool.Begin(ctx)
	if err != nil {
		return clairerror.ErrPutNotifications{opts.NotificationID, err}
	}
	defer tx.Rollback(ctx)

	// insert into identity table
	tag, err := tx.Exec(ctx, insertNotification, opts.NotificationID)
	if err != nil {
		return clairerror.ErrPutNotifications{opts.NotificationID, err}
	}
	if tag.RowsAffected() <= 0 {
		return clairerror.ErrPutNotifications{opts.NotificationID, fmt.Errorf("no rows affected when inserting notification identity")}
	}

	// batch insert notifications
	mBatch := microbatch.NewInsert(tx, batchSize, batchTO)
	for _, notification := range opts.Notifications {
		id := uuid.New()
		notification.ID = id
		if err := mBatch.Queue(ctx, insertNotifcationBody, id, opts.NotificationID, notificationJSONB(notification)); err != nil {
			return clairerror.ErrPutNotifications{opts.NotificationID, err}
		}
	}
	err = mBatch.Done(ctx)
	if err != nil {
		return clairerror.ErrPutNotifications{opts.NotificationID, err}
	}

	// update known update operations
	_, err = tx.Exec(ctx, insertUpdateOperation, opts.Updater, opts.UpdateID, time.Now())
	if err != nil {
		return clairerror.ErrPutNotifications{opts.NotificationID, err}
	}

	// create receipt
	tag, err = tx.Exec(ctx, insertReceipt, opts.NotificationID, opts.UpdateID)
	if err != nil {
		return clairerror.ErrPutNotifications{opts.NotificationID, err}
	}
	if tag.RowsAffected() <= 0 {
		return clairerror.ErrPutNotifications{opts.NotificationID, fmt.Errorf("no rows affected when creating a receipt")}
	}

	err = tx.Commit(ctx)
	if err != nil {
		return clairerror.ErrPutNotifications{opts.NotificationID, err}
	}
	return nil
}
