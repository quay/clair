package notifier

import (
	"context"

	"github.com/google/uuid"
)

// MockStore implements a mock Store.
type MockStore struct {
	Notifications_         func(ctx context.Context, id uuid.UUID, page *Page) ([]Notification, Page, error)
	PutNotifications_      func(ctx context.Context, opts PutOpts) error
	PutReceipt_            func(ctx context.Context, updater string, r Receipt) error
	CollectNotitfications_ func(ctx context.Context) error
	Receipt_               func(ctx context.Context, id uuid.UUID) (Receipt, error)
	ReceiptByUOID_         func(ctx context.Context, id uuid.UUID) (Receipt, error)
	Created_               func(ctx context.Context) ([]uuid.UUID, error)
	Failed_                func(ctx context.Context) ([]uuid.UUID, error)
	Deleted_               func(ctx context.Context) ([]uuid.UUID, error)
	SetDelivered_          func(ctx context.Context, id uuid.UUID) error
	SetDeliveredFailed_    func(ctx context.Context, id uuid.UUID) error
	SetDeleted_            func(ctx context.Context, id uuid.UUID) error
}

// Notifications retrieves the list of notifications associated with a
// notification id
func (m *MockStore) Notifications(ctx context.Context, id uuid.UUID, page *Page) ([]Notification, Page, error) {
	return m.Notifications_(ctx, id, page)
}

// PutNotifications persists the provided notifications and associates
// them with the provided notification id
//
// PutNotifications must update the latest update operation for the provided
// updater in such a way that UpdateOperation returns the provided update
// operation id when queried with the updater name
//
// PutNotifications must create a Receipt with status created status on
// successful persistence of notifications in such a way that Receipter.Created()
// returns the persisted notification id.
func (m *MockStore) PutNotifications(ctx context.Context, opts PutOpts) error {
	return m.PutNotifications_(ctx, opts)
}

// PutReceipt allows for the caller to directly add a receipt to the store
// without notifications being created.
//
// After this method returns all methods on the Receipter interface must work accordingly.
func (m *MockStore) PutReceipt(ctx context.Context, updater string, r Receipt) error {
	return m.PutReceipt_(ctx, updater, r)
}

// CollectNotifications garbage collects all notifications.
func (m *MockStore) CollectNotifications(ctx context.Context) error {
	return m.CollectNotitfications_(ctx)
}

// Receipt returns the Receipt for a given notification id
func (m *MockStore) Receipt(ctx context.Context, id uuid.UUID) (Receipt, error) {
	return m.Receipt_(ctx, id)
}

// ReceiptByUOID returns the Receipt for a given UOID
func (m *MockStore) ReceiptByUOID(ctx context.Context, id uuid.UUID) (Receipt, error) {
	return m.ReceiptByUOID_(ctx, id)
}

// Created returns a slice of notification ids in created status
func (m *MockStore) Created(ctx context.Context) ([]uuid.UUID, error) {
	return m.Created_(ctx)
}

// Failed returns a slice of notification ids in failed status
func (m *MockStore) Failed(ctx context.Context) ([]uuid.UUID, error) {
	return m.Failed_(ctx)
}

// Deleted returns a slice of notification ids in deleted status
func (m *MockStore) Deleted(ctx context.Context) ([]uuid.UUID, error) {
	return m.Deleted_(ctx)
}

// SetDelivered marks the provided notification id as delivered
func (m *MockStore) SetDelivered(ctx context.Context, id uuid.UUID) error {
	return m.SetDelivered_(ctx, id)
}

// SetDeliveryFailed marks the provided notification id failed to be delivere
func (m *MockStore) SetDeliveryFailed(ctx context.Context, id uuid.UUID) error {
	return m.SetDeliveredFailed_(ctx, id)
}

// SetDeleted marks the provided notification id as deleted
func (m *MockStore) SetDeleted(ctx context.Context, id uuid.UUID) error {
	return m.SetDeleted_(ctx, id)
}
