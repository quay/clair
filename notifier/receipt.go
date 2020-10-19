package notifier

import (
	"time"

	"github.com/google/uuid"
)

// Status defines the possible states of a notification.
type Status string

const (
	// A notification is created and ready to be delivered to a client
	Created Status = "created"
	// A notification has been successfully delivered to a client
	Delivered Status = "delivered"
	// A notification failed to be delivered
	DeliveryFailed Status = "delivery_failed"
	// The client has read the notification and issued a delete
	Deleted Status = "deleted"
)

// Receipt represents the current status of a notification
type Receipt struct {
	// The update operation associated with this receipt
	UOID uuid.UUID
	// the id a client may use to retrieve a set of notifications
	NotificationID uuid.UUID
	// the current status  of the notification
	Status Status
	// the timestamp of the last status update
	TS time.Time
}
