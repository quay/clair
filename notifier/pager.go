package notifier

import (
	"github.com/google/uuid"
)

// Page communicates a bare-minimum paging protocol with clients.
type Page struct {
	// the next id to retrieve
	Next *uuid.UUID `json:"next,omitempty"`
	// the max number of elements returned in a page
	Size int `json:"size"`
}
