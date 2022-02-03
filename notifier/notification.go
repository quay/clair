package notifier

import (
	"github.com/google/uuid"
	"github.com/quay/claircore"
)

// Reason indicates the catalyst for a notification.
type Reason string

const (
	Added   Reason = "added"
	Removed Reason = "removed"
	Changed Reason = "changed"
)

// Notification summarizes a change in the vulnerabilities affecting a manifest.
//
// The mentioned Vulnerability will be the most severe vulnerability discovered
// in an update operation.
//
// Receiving clients are expected to filter notifications by severity in such a
// way that they receive all vulnerabilities at or above a particular
// claircore.Severity level.
type Notification struct {
	ID            uuid.UUID        `json:"id"`
	Manifest      claircore.Digest `json:"manifest"`
	Reason        Reason           `json:"reason"`
	Vulnerability VulnSummary      `json:"vulnerability"`
}
