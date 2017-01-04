// Copyright 2017 clair authors
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

// Package notification fetches notifications from the database and informs the
// specified remote handler about their existences, inviting the third party to
// actively query the API about it.

// Package notification exposes functions to dynamically register methods to
// deliver notifications from the Clair database.
package notification

import (
	"github.com/coreos/pkg/capnslog"

	"github.com/coreos/clair/config"
	"github.com/coreos/clair/database"
)

var (
	log = capnslog.NewPackageLogger("github.com/coreos/clair", "ext/notification")

	// Senders is the list of registered Senders.
	Senders = make(map[string]Sender)
)

// Sender represents anything that can transmit notifications.
type Sender interface {
	// Configure attempts to initialize the notifier with the provided configuration.
	// It returns whether the notifier is enabled or not.
	Configure(*config.NotifierConfig) (bool, error)

	// Send informs the existence of the specified notification.
	Send(notification database.VulnerabilityNotification) error
}

// RegisterSender makes a Sender available by the provided name.
//
// If RegisterSender is called twice with the same name, the name is blank, or
// if the provided Sender is nil, this function panics.
func RegisterSender(name string, s Sender) {
	if name == "" {
		panic("notification: could not register a Sender with an empty name")
	}

	if s == nil {
		panic("notification: could not register a nil Sender")
	}

	if _, dup := Senders[name]; dup {
		panic("notification: RegisterSender called twice for " + name)
	}

	Senders[name] = s
}
