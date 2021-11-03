package postgres

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/quay/clair/v4/notifier"
)

// Store implements the notifier.Store interface
type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool}
}

// Notifications retrieves the list of notifications associated with a
// notification id
func (s *Store) Notifications(ctx context.Context, id uuid.UUID, page *notifier.Page) ([]notifier.Notification, notifier.Page, error) {
	return notifications(ctx, s.pool, id, page)
}

// PutNotifications persists the provided notifications and associates
// them with the provided notification id
//
// PutNotifications must update the latest update operation for the provided
// updater in such a way that UpdateOperation returns the the provided update
// operation id when queried with the updater name
//
// PutNotifications must create a Receipt with status created status on
// successful persistence of notifications in such a way that Receipter.Created()
// returns the persisted notification id.
func (s *Store) PutNotifications(ctx context.Context, opts notifier.PutOpts) error {
	return putNotifications(ctx, s.pool, opts)
}

func (s *Store) PutReceipt(ctx context.Context, updater string, r notifier.Receipt) error {
	return putReceipt(ctx, s.pool, updater, r)
}

// DeleteNotifications garbage collects all notifications associated
// with a notification id.
//
// Normally Receipter.SetDeleted will be issues first, however
// application logic may decide to gc notifications which have not been
// set deleted after some period of time, thus this condition should not
// be checked.
func (s *Store) DeleteNotifications(ctx context.Context, id uuid.UUID) error {
	return deleteNotifications(ctx, s.pool, id)
}

// Receipt returns the Receipt for a given notification id
func (s *Store) Receipt(ctx context.Context, id uuid.UUID) (notifier.Receipt, error) {
	return receipt(ctx, s.pool, id)
}

// ReceiptByUOID returns the Receipt for a given notification UOID
func (s *Store) ReceiptByUOID(ctx context.Context, id uuid.UUID) (notifier.Receipt, error) {
	return receiptByUOID(ctx, s.pool, id)
}

// Created returns a slice of notification ids in created status
func (s *Store) Created(ctx context.Context) ([]uuid.UUID, error) {
	return created(ctx, s.pool)
}

// Failed returns a slice of notification ids in failed status
func (s *Store) Failed(ctx context.Context) ([]uuid.UUID, error) {
	return failed(ctx, s.pool)
}

// Deleted returns a slice of notification ids in deleted status
func (s *Store) Deleted(ctx context.Context) ([]uuid.UUID, error) {
	return deleted(ctx, s.pool)
}

// SetDelivered marks the provided notification id as delivered
func (s *Store) SetDelivered(ctx context.Context, id uuid.UUID) error {
	return setDelivered(ctx, s.pool, id)
}

// SetDeliveryFailed marks the provided notification id failed to be delivered
func (s *Store) SetDeliveryFailed(ctx context.Context, id uuid.UUID) error {
	return setDeliveryFailed(ctx, s.pool, id)
}

// SetDeleted marks the provided notification id as deleted
func (s *Store) SetDeleted(ctx context.Context, id uuid.UUID) error {
	return setDeleted(ctx, s.pool, id)
}
