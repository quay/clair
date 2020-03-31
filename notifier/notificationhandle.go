package notifier

import "github.com/google/uuid"

// NotificationHandle is a handle a client may use to
// retrieve a list of associated notification models
type NotificationHandle struct {
	ID uuid.UUID `json:"id"`
}
