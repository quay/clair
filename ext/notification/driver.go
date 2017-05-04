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
	"sync"
	"time"

	"github.com/coreos/clair/database"
)

var (
	sendersM sync.RWMutex
	senders  = make(map[string]Sender)
)

// Config is the configuration for the Notifier service and its registered
// notifiers.
type Config struct {
	Attempts         int
	RenotifyInterval time.Duration
	Params           map[string]interface{} `yaml:",inline"`
}

// Sender represents anything that can transmit notifications.
type Sender interface {
	// Configure attempts to initialize the notifier with the provided configuration.
	// It returns whether the notifier is enabled or not.
	Configure(*Config) (bool, error)

	// Send informs the existence of the specified notification.
	Send(notification database.VulnerabilityNotification) error
}

// RegisterSender makes a Sender available by the provided name.
//
// If called twice with the same name, the name is blank, or if the provided
// Sender is nil, this function panics.
func RegisterSender(name string, s Sender) {
	if name == "" {
		panic("notification: could not register a Sender with an empty name")
	}

	if s == nil {
		panic("notification: could not register a nil Sender")
	}

	sendersM.Lock()
	defer sendersM.Unlock()

	if _, dup := senders[name]; dup {
		panic("notification: RegisterSender called twice for " + name)
	}

	senders[name] = s
}

// Senders returns the list of the registered Senders.
func Senders() map[string]Sender {
	sendersM.RLock()
	defer sendersM.RUnlock()

	ret := make(map[string]Sender)
	for k, v := range senders {
		ret[k] = v
	}

	return ret
}

// UnregisterSender removes a Sender with a particular name from the list.
func UnregisterSender(name string) {
	sendersM.Lock()
	defer sendersM.Unlock()

	delete(senders, name)
}
