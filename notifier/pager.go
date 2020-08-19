package notifier

import (
	"github.com/google/uuid"
)

// Page communicates a bare-minimum paging procotol with clients
type Page struct {
	// the max number of elements returned in a page
	Size uint64 `json:"size"`
	// the next id to retrieve
	Next *uuid.UUID `json:"next,omitempty"`
}
