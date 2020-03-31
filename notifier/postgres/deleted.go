package postgres

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v4/pgxpool"
	clairerror "github.com/quay/clair/v4/clair-error"
)

// deleted will return all notification ids in "deleted" status
func deleted(ctx context.Context, pool *pgxpool.Pool) ([]uuid.UUID, error) {
	const (
		query = `SELECT notification_id FROM receipt WHERE status = 'deleted'`
	)

	ids := make([]uuid.UUID, 0, 0)
	rows, _ := pool.Query(ctx, query)
	defer rows.Close()
	for rows.Next() {
		var id uuid.UUID
		err := rows.Scan(&id)
		if err != nil {
			return nil, clairerror.ErrCreated{err}
		}
		ids = append(ids, id)
	}

	return ids, nil
}
