package service

import (
	"context"

	"github.com/google/uuid"

	"github.com/quay/clair/v4/notifier"
)

var _ notifier.Service = (*Mock)(nil)

// Mock implements a mock notifier service
type Mock struct {
	Notifications_       func(ctx context.Context, id uuid.UUID, page *notifier.Page) ([]notifier.Notification, notifier.Page, error)
	DeleteNotifications_ func(ctx context.Context, id uuid.UUID) error
}

func (m *Mock) Notifications(ctx context.Context, id uuid.UUID, page *notifier.Page) ([]notifier.Notification, notifier.Page, error) {
	return m.Notifications_(ctx, id, page)
}

func (m *Mock) DeleteNotifications(ctx context.Context, id uuid.UUID) error {
	return m.DeleteNotifications_(ctx, id)
}
