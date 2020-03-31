package postgres

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v4/pgxpool"
	clairerror "github.com/quay/clair/v4/clair-error"
)

// setDeleted will update the receipt's status to "deleted" for the provied
// notification id
func setDeleted(ctx context.Context, pool *pgxpool.Pool, id uuid.UUID) error {
	const (
		query = `UPDATE receipt SET status = 'deleted', ts = CURRENT_TIMESTAMP WHERE notification_id = $1`
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
