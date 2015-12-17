// Copyright 2015 clair authors
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

// Package notifier fetches notifications from the database and sends them
// to the specified remote handler.
package notifier

import (
	"time"

	"github.com/coreos/pkg/capnslog"
	"github.com/coreos/pkg/timeutil"
	"github.com/pborman/uuid"

	"github.com/coreos/clair/config"
	"github.com/coreos/clair/database"
	"github.com/coreos/clair/health"
	"github.com/coreos/clair/utils"
)

var log = capnslog.NewPackageLogger("github.com/coreos/clair", "notifier")

const (
	checkInterval       = 5 * time.Minute
	refreshLockDuration = time.Minute * 2
	lockDuration        = time.Minute*8 + refreshLockDuration
	maxBackOff          = 15 * time.Minute
)

// TODO(Quentin-M): Allow registering custom notification handlers.

// A Notification represents the structure of the notifications that are sent by a Notifier.
type Notification struct {
	Name, Type string
	Content    interface{}
}

var notifiers = make(map[string]Notifier)

// Notifier represents anything that can transmit notifications.
type Notifier interface {
	// Configure attempts to initialize the notifier with the provided configuration.
	// It returns whether the notifier is enabled or not.
	Configure(*config.NotifierConfig) (bool, error)
	// Send transmits the specified notification.
	Send(notification *Notification) error
}

// RegisterNotifier makes a Fetcher available by the provided name.
// If Register is called twice with the same name or if driver is nil,
// it panics.
func RegisterNotifier(name string, n Notifier) {
	if name == "" {
		panic("notifier: could not register a Notifier with an empty name")
	}

	if n == nil {
		panic("notifier: could not register a nil Notifier")
	}

	if _, dup := notifiers[name]; dup {
		panic("notifier: RegisterNotifier called twice for " + name)
	}

	notifiers[name] = n
}

// Run starts the Notifier service.
func Run(config *config.NotifierConfig, stopper *utils.Stopper) {
	defer stopper.End()

	// Configure registered notifiers.
	for notifierName, notifier := range notifiers {
		if configured, err := notifier.Configure(config); configured {
			log.Infof("notifier '%s' configured\n", notifierName)
		} else {
			delete(notifiers, notifierName)
			if err != nil {
				log.Errorf("could not configure notifier '%s': %s", notifierName, err)
			}
		}
	}

	// Do not run the updater if there is no notifier enabled.
	if len(notifiers) == 0 {
		log.Infof("notifier service is disabled")
		return
	}

	whoAmI := uuid.New()
	log.Infof("notifier service started. lock identifier: %s\n", whoAmI)

	// Register healthchecker.
	health.RegisterHealthchecker("notifier", Healthcheck)

	for running := true; running; {
		// Find task.
		// TODO(Quentin-M): Combine node and notification.
		node, notification := findTask(whoAmI, stopper)
		if node == "" && notification == nil {
			// Interrupted while finding a task, Clair is stopping.
			break
		}

		// Handle task.
		done := make(chan bool, 1)
		go func() {
			success, interrupted := handleTask(notification, stopper, config.Attempts)
			if success {
				database.MarkNotificationAsSent(node)
			}
			if interrupted {
				running = false
			}
			database.Unlock(node, whoAmI)
			done <- true
		}()

		// Refresh task lock until done.
	outer:
		for {
			select {
			case <-done:
				break outer
			case <-time.After(refreshLockDuration):
				database.Lock(node, lockDuration, whoAmI)
			}
		}
	}

	log.Info("notifier service stopped")
}

func findTask(whoAmI string, stopper *utils.Stopper) (string, database.Notification) {
	for {
		// Find a notification to send.
		node, notification, err := database.FindOneNotificationToSend(database.GetDefaultNotificationWrapper())
		if err != nil {
			log.Warningf("could not get notification to send: %s", err)
		}

		// No notification or error: wait.
		if notification == nil || err != nil {
			if !stopper.Sleep(checkInterval) {
				return "", nil
			}
			continue
		}

		// Lock the notification.
		if hasLock, _ := database.Lock(node, lockDuration, whoAmI); hasLock {
			log.Infof("found and locked a notification: %s", notification.GetName())
			return node, notification
		}
	}
}

func handleTask(notification database.Notification, st *utils.Stopper, maxAttempts int) (bool, bool) {
	// Get notification content.
	// TODO(Quentin-M): Split big notifications.
	notificationContent, err := notification.GetContent()
	if err != nil {
		log.Warningf("could not get content of notification '%s': %s", notification.GetName(), err)
		return false, false
	}

	// Create notification.
	payload := &Notification{
		Name:    notification.GetName(),
		Type:    notification.GetType(),
		Content: notificationContent,
	}

	// Send notification.
	for notifierName, notifier := range notifiers {
		var attempts int
		var backOff time.Duration
		for {
			// Max attempts exceeded.
			if attempts >= maxAttempts {
				log.Infof("giving up on sending notification '%s' to notifier '%s': max attempts exceeded (%d)\n", notification.GetName(), notifierName, maxAttempts)
				return false, false
			}

			// Backoff.
			if backOff > 0 {
				log.Infof("waiting %v before retrying to send notification '%s' to notifier '%s' (Attempt %d / %d)\n", backOff, notification.GetName(), notifierName, attempts+1, maxAttempts)
				if !st.Sleep(backOff) {
					return false, true
				}
			}

			// Send using the current notifier.
			if err := notifier.Send(payload); err == nil {
				// Send has been successful. Go to the next one.
				break
			}

			// Send failed; increase attempts/backoff and retry.
			log.Errorf("could not send notification '%s' to notifier '%s': %s", notification.GetName(), notifierName, err)
			backOff = timeutil.ExpBackoff(backOff, maxBackOff)
			attempts++
		}
	}

	log.Infof("successfully sent notification '%s'\n", notification.GetName())
	return true, false
}

// Healthcheck returns the health of the notifier service.
func Healthcheck() health.Status {
	queueSize, err := database.CountNotificationsToSend()
	return health.Status{IsEssential: false, IsHealthy: err == nil, Details: struct{ QueueSize int }{QueueSize: queueSize}}
}
