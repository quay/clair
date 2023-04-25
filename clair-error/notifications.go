package clairerror

import (
	"fmt"

	"github.com/google/uuid"
)

// ErrNoUpdateOperation inidcates that the queried updater has no
// update operations associated.
type ErrNoUpdateOperation struct {
	Updater string
}

func (e ErrNoUpdateOperation) Error() string {
	return fmt.Sprintf("updater %s has no associated update operations", e.Updater)
}

// ErrBadNotification indicates a notification was malformed.
// The wrapped error will contain further details.
type ErrBadNotification struct {
	NotificationID uuid.UUID
	E              error
}

func (e ErrBadNotification) Error() string {
	return fmt.Sprintf("notification associated with id %s is malformed: %v", e.NotificationID, e.E)
}

func (e ErrBadNotification) Unwrap() error {
	return e.E
}

// ErrDeleteNotification indicates an error while deleting notifcations.
// The wrapped error will contain further details.
type ErrDeleteNotification struct {
	NotificationID uuid.UUID
	E              error
}

func (e ErrDeleteNotification) Error() string {
	return fmt.Sprintf("notifications associated with id %s were not deleted: %v", e.NotificationID, e.E)
}

func (e ErrDeleteNotification) Unwrap() error {
	return e.E
}

// ErrNoReceipt is returned when a notification id has no associated Receipt.
type ErrNoReceipt struct {
	NotificationID uuid.UUID
}

func (e ErrNoReceipt) Error() string {
	return fmt.Sprintf("no receipt exists for notification id %s", e.NotificationID)
}

// ErrReceipt indicates an error retreiving a receipt for referenced notification id.
type ErrReceipt struct {
	NotificationID uuid.UUID
	E              error
}

func (e ErrReceipt) Error() string {
	return fmt.Sprintf("failed to retrieve receipt for notification id %s: %v", e.NotificationID, e.E)
}

func (e ErrReceipt) Unwrap() error {
	return e.E
}

// ErrCreated indicates an error occurred when retrieving created notification ids.
type ErrCreated struct {
	E error
}

func (e ErrCreated) Error() string {
	return fmt.Sprintf("failed to retrieve created notification ids: %v", e.E)
}

func (e ErrCreated) Unwrap() error {
	return e.E
}

// ErrFailed indicates an error occurred when retrieving created notification ids.
type ErrFailed struct {
	E error
}

func (e ErrFailed) Error() string {
	return fmt.Sprintf("failed to retrieve failed notification ids: %v", e.E)
}

func (e ErrFailed) Unwrap() error {
	return e.E
}

// ErrPutNotifications indicates an issues occurred when persisting a slice of
// computed notifications.
// The wrapped error will contain further details.
type ErrPutNotifications struct {
	NotificationID uuid.UUID
	E              error
}

func (e ErrPutNotifications) Error() string {
	return fmt.Sprintf("failed to persist notification associated with id %s: %v", e.NotificationID.String(), e.E)
}

func (e ErrPutNotifications) Unwrap() error {
	return e.E
}

// ErrDeliveryFailed indicates a failure to deliver a notification.
type ErrDeliveryFailed struct {
	E error
}

func (e ErrDeliveryFailed) Error() string {
	return "failed to deliver notification: " + e.E.Error()
}

func (e ErrDeliveryFailed) Unwrap() error {
	return e.E
}
