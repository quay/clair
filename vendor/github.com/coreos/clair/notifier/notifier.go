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

// Package notifier fetches notifications from the database and informs the specified remote handler
// about their existences, inviting the third party to actively query the API about it.
package notifier

import (
	"time"

	"github.com/coreos/pkg/capnslog"
	"github.com/coreos/pkg/timeutil"
	"github.com/pborman/uuid"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/coreos/clair/config"
	"github.com/coreos/clair/database"
	"github.com/coreos/clair/utils"
	cerrors "github.com/coreos/clair/utils/errors"
)

const (
	checkInterval       = 5 * time.Minute
	refreshLockDuration = time.Minute * 2
	lockDuration        = time.Minute*8 + refreshLockDuration
	maxBackOff          = 15 * time.Minute
)

var (
	log = capnslog.NewPackageLogger("github.com/coreos/clair", "notifier")

	notifiers = make(map[string]Notifier)

	promNotifierLatencyMilliseconds = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name: "clair_notifier_latency_milliseconds",
		Help: "Time it takes to send a notification after it's been created.",
	})

	promNotifierBackendErrorsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "clair_notifier_backend_errors_total",
		Help: "Number of errors that notifier backends generated.",
	}, []string{"backend"})
)

// Notifier represents anything that can transmit notifications.
type Notifier interface {
	// Configure attempts to initialize the notifier with the provided configuration.
	// It returns whether the notifier is enabled or not.
	Configure(*config.NotifierConfig) (bool, error)
	// Send informs the existence of the specified notification.
	Send(notification database.VulnerabilityNotification) error
}

func init() {
	prometheus.MustRegister(promNotifierLatencyMilliseconds)
	prometheus.MustRegister(promNotifierBackendErrorsTotal)
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
func Run(config *config.NotifierConfig, datastore database.Datastore, stopper *utils.Stopper) {
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

	for running := true; running; {
		// Find task.
		notification := findTask(datastore, config.RenotifyInterval, whoAmI, stopper)
		if notification == nil {
			// Interrupted while finding a task, Clair is stopping.
			break
		}

		// Handle task.
		done := make(chan bool, 1)
		go func() {
			success, interrupted := handleTask(*notification, stopper, config.Attempts)
			if success {
				utils.PrometheusObserveTimeMilliseconds(promNotifierLatencyMilliseconds, notification.Created)
				datastore.SetNotificationNotified(notification.Name)
			}
			if interrupted {
				running = false
			}
			datastore.Unlock(notification.Name, whoAmI)
			done <- true
		}()

		// Refresh task lock until done.
	outer:
		for {
			select {
			case <-done:
				break outer
			case <-time.After(refreshLockDuration):
				datastore.Lock(notification.Name, whoAmI, lockDuration, true)
			}
		}
	}

	log.Info("notifier service stopped")
}

func findTask(datastore database.Datastore, renotifyInterval time.Duration, whoAmI string, stopper *utils.Stopper) *database.VulnerabilityNotification {
	for {
		// Find a notification to send.
		notification, err := datastore.GetAvailableNotification(renotifyInterval)
		if err != nil {
			// There is no notification or an error occurred.
			if err != cerrors.ErrNotFound {
				log.Warningf("could not get notification to send: %s", err)
			}

			// Wait.
			if !stopper.Sleep(checkInterval) {
				return nil
			}

			continue
		}

		// Lock the notification.
		if hasLock, _ := datastore.Lock(notification.Name, whoAmI, lockDuration, false); hasLock {
			log.Infof("found and locked a notification: %s", notification.Name)
			return &notification
		}
	}
}

func handleTask(notification database.VulnerabilityNotification, st *utils.Stopper, maxAttempts int) (bool, bool) {
	// Send notification.
	for notifierName, notifier := range notifiers {
		var attempts int
		var backOff time.Duration
		for {
			// Max attempts exceeded.
			if attempts >= maxAttempts {
				log.Infof("giving up on sending notification '%s' via notifier '%s': max attempts exceeded (%d)\n", notification.Name, notifierName, maxAttempts)
				return false, false
			}

			// Backoff.
			if backOff > 0 {
				log.Infof("waiting %v before retrying to send notification '%s' via notifier '%s' (Attempt %d / %d)\n", backOff, notification.Name, notifierName, attempts+1, maxAttempts)
				if !st.Sleep(backOff) {
					return false, true
				}
			}

			// Send using the current notifier.
			if err := notifier.Send(notification); err != nil {
				// Send failed; increase attempts/backoff and retry.
				promNotifierBackendErrorsTotal.WithLabelValues(notifierName).Inc()
				log.Errorf("could not send notification '%s' via notifier '%s': %v", notification.Name, notifierName, err)
				backOff = timeutil.ExpBackoff(backOff, maxBackOff)
				attempts++
				continue
			}

			// Send has been successful. Go to the next notifier.
			break
		}
	}

	log.Infof("successfully sent notification '%s'\n", notification.Name)
	return true, false
}
