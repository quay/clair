package notifier

import (
	"context"

	"github.com/google/uuid"
)

// Service is an interface wrapping ClairV4's notifier functionality.
//
// This remains an interface so remote clients may implement as well.
type Service interface {
	// Retrieves an optional paginated set of notifications given an notification id
	Notifications(ctx context.Context, id uuid.UUID, page *Page) ([]Notification, Page, error)
	// Deletes the provided notification id
	DeleteNotifications(ctx context.Context, id uuid.UUID) error
}
