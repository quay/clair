// Copyright 2019 clair authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package database

import (
	"time"

	"github.com/coreos/clair/pkg/pagination"
)

// NotificationHook is a message sent to another service to inform of a change
// to a Vulnerability or the Ancestries affected by a Vulnerability. It contains
// the name of a notification that should be read and marked as read via the
// API.
type NotificationHook struct {
	Name string

	Created  time.Time
	Notified time.Time
	Deleted  time.Time
}

// VulnerabilityNotification is a notification for vulnerability changes.
type VulnerabilityNotification struct {
	NotificationHook

	Old *Vulnerability
	New *Vulnerability
}

// VulnerabilityNotificationWithVulnerable is a notification for vulnerability
// changes with vulnerable ancestries.
type VulnerabilityNotificationWithVulnerable struct {
	NotificationHook

	Old *PagedVulnerableAncestries
	New *PagedVulnerableAncestries
}

// PagedVulnerableAncestries is a vulnerability with a page of affected
// ancestries each with a special index attached for streaming purpose. The
// current page number and next page number are for navigate.
type PagedVulnerableAncestries struct {
	Vulnerability

	// Affected is a map of special indexes to Ancestries, which the pair
	// should be unique in a stream. Every indexes in the map should be larger
	// than previous page.
	Affected map[int]string

	Limit   int
	Current pagination.Token
	Next    pagination.Token

	// End signals the end of the pages.
	End bool
}
