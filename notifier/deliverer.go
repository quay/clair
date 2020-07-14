package notifier

import (
	"context"

	"github.com/google/uuid"
)

// Deliverer provides the method set for delivering notifications
type Deliverer interface {
	// A unique name for the deliverer implementation
	Name() string
	// Deliver will push the notification ID to subscribed clients.
	//
	// If delivery fails a clairerror.ErrDeliveryFailed error must be returned.
	Deliver(ctx context.Context, nID uuid.UUID) error
}

// DirectDeliverer implementations are used in coordination with the Deliverer interface.
//
// DirectDeliverer(s) expect this method to be called prior to their Deliverer methods.
// Implementations must still implement both Deliverer and DirectDeliverer methods for correct use.
//
// Implementations will be provided a list of notifications in which they can directly deliver to subscribed
// clients.
type DirectDeliverer interface {
	Notifications(ctx context.Context, n []Notification) error
}
