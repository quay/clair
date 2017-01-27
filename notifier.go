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

package clair

import (
	"time"

	"github.com/coreos/pkg/timeutil"
	"github.com/pborman/uuid"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/ext/notification"
	"github.com/coreos/clair/pkg/commonerr"
	"github.com/coreos/clair/pkg/stopper"
)

const (
	notifierCheckInterval       = 5 * time.Minute
	notifierMaxBackOff          = 15 * time.Minute
	notifierLockRefreshDuration = time.Minute * 2
	notifierLockDuration        = time.Minute*8 + notifierLockRefreshDuration
)

var (
	promNotifierLatencyMilliseconds = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name: "clair_notifier_latency_milliseconds",
		Help: "Time it takes to send a notification after it's been created.",
	})

	promNotifierBackendErrorsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "clair_notifier_backend_errors_total",
		Help: "Number of errors that notifier backends generated.",
	}, []string{"backend"})
)

func init() {
	prometheus.MustRegister(promNotifierLatencyMilliseconds)
	prometheus.MustRegister(promNotifierBackendErrorsTotal)
}

// RunNotifier begins a process that checks for new notifications that should
// be sent out to third parties.
func RunNotifier(config *notification.Config, datastore database.Datastore, stopper *stopper.Stopper) {
	defer stopper.End()

	// Configure registered notifiers.
	for senderName, sender := range notification.Senders() {
		if configured, err := sender.Configure(config); configured {
			log.Infof("sender '%s' configured\n", senderName)
		} else {
			notification.UnregisterSender(senderName)
			if err != nil {
				log.Errorf("could not configure notifier '%s': %s", senderName, err)
			}
		}
	}

	// Do not run the updater if there is no notifier enabled.
	if len(notification.Senders()) == 0 {
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
				datastore.SetNotificationNotified(notification.Name)

				promNotifierLatencyMilliseconds.Observe(float64(time.Since(notification.Created).Nanoseconds()) / float64(time.Millisecond))
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
			case <-time.After(notifierLockRefreshDuration):
				datastore.Lock(notification.Name, whoAmI, notifierLockDuration, true)
			}
		}
	}

	log.Info("notifier service stopped")
}

func findTask(datastore database.Datastore, renotifyInterval time.Duration, whoAmI string, stopper *stopper.Stopper) *database.VulnerabilityNotification {
	for {
		// Find a notification to send.
		notification, err := datastore.GetAvailableNotification(renotifyInterval)
		if err != nil {
			// There is no notification or an error occurred.
			if err != commonerr.ErrNotFound {
				log.Warningf("could not get notification to send: %s", err)
			}

			// Wait.
			if !stopper.Sleep(notifierCheckInterval) {
				return nil
			}

			continue
		}

		// Lock the notification.
		if hasLock, _ := datastore.Lock(notification.Name, whoAmI, notifierLockDuration, false); hasLock {
			log.Infof("found and locked a notification: %s", notification.Name)
			return &notification
		}
	}
}

func handleTask(n database.VulnerabilityNotification, st *stopper.Stopper, maxAttempts int) (bool, bool) {
	// Send notification.
	for senderName, sender := range notification.Senders() {
		var attempts int
		var backOff time.Duration
		for {
			// Max attempts exceeded.
			if attempts >= maxAttempts {
				log.Infof("giving up on sending notification '%s' via sender '%s': max attempts exceeded (%d)\n", n.Name, senderName, maxAttempts)
				return false, false
			}

			// Backoff.
			if backOff > 0 {
				log.Infof("waiting %v before retrying to send notification '%s' via sender '%s' (Attempt %d / %d)\n", backOff, n.Name, senderName, attempts+1, maxAttempts)
				if !st.Sleep(backOff) {
					return false, true
				}
			}

			// Send using the current notifier.
			if err := sender.Send(n); err != nil {
				// Send failed; increase attempts/backoff and retry.
				promNotifierBackendErrorsTotal.WithLabelValues(senderName).Inc()
				log.Errorf("could not send notification '%s' via notifier '%s': %v", n.Name, senderName, err)
				backOff = timeutil.ExpBackoff(backOff, notifierMaxBackOff)
				attempts++
				continue
			}

			// Send has been successful. Go to the next notifier.
			break
		}
	}

	log.Infof("successfully sent notification '%s'\n", n.Name)
	return true, false
}
