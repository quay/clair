package notifier

import (
	"context"

	"github.com/google/uuid"
)

// PutOpts is provided to Notificationer.Put
// with fields necessary to persist a notification id
type PutOpts struct {
	// the updater triggering a notification
	Updater string
	// the update operation id triggering the notification
	UpdateID uuid.UUID
	// the notification id clients will use to retrieve the
	// list of notifications
	NotificationID uuid.UUID
	// a slice of notifications to persist. these notifications
	// will be retrievable via the notification id
	Notifications []Notification
}

// Store is an aggregate interface implementing all methods
// necessary for a notifier persistence layer
type Store interface {
	Notificationer
	Receipter
}

// Notificationer implements persistence methods for Notification models
type Notificationer interface {
	// Notifications retrieves the list of notifications associated with a
	// notification id
	//
	// If a Page is provided the returned notifications will be a subset of the total
	// and it's len will be no larger then Page.Size.
	//
	// This method should interpret the page.Next field as the requested page and
	// set the returned page.Next field to the next page to receive or -1 if
	// paging has been exhausted.
	//
	// Page maybe nil to receive all notifications.
	Notifications(ctx context.Context, id uuid.UUID, page *Page) ([]Notification, Page, error)
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
	PutNotifications(ctx context.Context, opts PutOpts) error
	// PutReceipt allows for the caller to directly add a receipt to the store
	// without notifications being created.
	//
	// After this method returns all methods on the Receipter interface must work accordingly.
	PutReceipt(ctx context.Context, updater string, r Receipt) error
	// CollectNotifications garbage collects all notifications.
	//
	// Normally Receipter.SetDeleted will be issues first, however
	// application logic may decide to GC notifications which have not been
	// set deleted after some period of time, thus this condition should not
	// be checked.
	CollectNotifications(ctx context.Context) error
}

// Receipter implements persistence methods for Receipt models
type Receipter interface {
	// Receipt returns the Receipt for a given notification id
	Receipt(ctx context.Context, id uuid.UUID) (Receipt, error)
	// ReceiptByUOID returns the Receipt for a given UOID
	ReceiptByUOID(ctx context.Context, id uuid.UUID) (Receipt, error)
	// Created returns a slice of notification ids in created status
	Created(ctx context.Context) ([]uuid.UUID, error)
	// Failed returns a slice of notification ids to in delivery failed status
	Failed(ctx context.Context) ([]uuid.UUID, error)
	// Deleted returns a slice of notification ids in deleted status
	Deleted(ctx context.Context) ([]uuid.UUID, error)
	// SetDelivered marks the provided notification id as delivered
	SetDelivered(ctx context.Context, id uuid.UUID) error
	// SetDeliveryFailed marks the provided notification id failed to be delivered
	SetDeliveryFailed(ctx context.Context, id uuid.UUID) error
	// SetDeleted marks the provided notification id as deleted
	SetDeleted(ctx context.Context, id uuid.UUID) error
}
