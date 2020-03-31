package postgres

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	clairerror "github.com/quay/clair/v4/clair-error"
	"github.com/quay/clair/v4/notifier"
)

// receipt returns a receipt for a given notification id
//
// if the receipt does not exist a ErrNoReceipt is returned
func receipt(ctx context.Context, pool *pgxpool.Pool, id uuid.UUID) (notifier.Receipt, error) {
	const (
		query = `SELECT notification_id, status, ts FROM receipt WHERE notification_id = $1`
	)

	var r notifier.Receipt
	row := pool.QueryRow(ctx, query, id.String())
	err := row.Scan(
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

	return r, nil
}
