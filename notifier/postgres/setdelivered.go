package postgres

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v4/pgxpool"
	clairerror "github.com/quay/clair/v4/clair-error"
)

// setDelivered will update the receipt's status to "delivered" for the provided
// notification id
func setDelivered(ctx context.Context, pool *pgxpool.Pool, id uuid.UUID) error {
	const (
		query = `UPDATE receipt SET status = 'delivered', ts = CURRENT_TIMESTAMP WHERE notification_id = $1`
	)

	tag, err := pool.Exec(ctx, query, id.String())
	if err != nil {
		return clairerror.ErrReceipt{id, err}
	}
	if tag.RowsAffected() <= 0 {
		return clairerror.ErrNoReceipt{id}
	}

	return nil
}
