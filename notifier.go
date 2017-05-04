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
	log "github.com/sirupsen/logrus"

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

	logSenderName = "sender name"
	logNotiName   = "notification name"
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
			log.WithField(logSenderName, senderName).Info("sender configured")
		} else {
			notification.UnregisterSender(senderName)
			if err != nil {
				log.WithError(err).WithField(logSenderName, senderName).Error("could not configure notifier")
			}
		}
	}

	// Do not run the updater if there is no notifier enabled.
	if len(notification.Senders()) == 0 {
		log.Info("notifier service is disabled")
		return
	}

	whoAmI := uuid.New()
	log.WithField("lock identifier", whoAmI).Info("notifier service started")

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
				log.WithError(err).Warning("could not get notification to send")
			}

			// Wait.
			if !stopper.Sleep(notifierCheckInterval) {
				return nil
			}

			continue
		}

		// Lock the notification.
		if hasLock, _ := datastore.Lock(notification.Name, whoAmI, notifierLockDuration, false); hasLock {
			log.WithField(logNotiName, notification.Name).Info("found and locked a notification")
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
				log.WithFields(log.Fields{logNotiName: n.Name, logSenderName: senderName, "max attempts": maxAttempts}).Info("giving up on sending notification : max attempts exceeded")
				return false, false
			}

			// Backoff.
			if backOff > 0 {
				log.WithFields(log.Fields{"duration": backOff, logNotiName: n.Name, logSenderName: senderName, "attempts": attempts + 1, "max attempts": maxAttempts}).Info("waiting before retrying to send notification")
				if !st.Sleep(backOff) {
					return false, true
				}
			}

			// Send using the current notifier.
			if err := sender.Send(n); err != nil {
				// Send failed; increase attempts/backoff and retry.
				promNotifierBackendErrorsTotal.WithLabelValues(senderName).Inc()
				log.WithError(err).WithFields(log.Fields{logSenderName: senderName, logNotiName: n.Name}).Error("could not send notification via notifier")
				backOff = timeutil.ExpBackoff(backOff, notifierMaxBackOff)
				attempts++
				continue
			}

			// Send has been successful. Go to the next notifier.
			break
		}
	}

	log.WithField(logNotiName, n.Name).Info("successfully sent notification")
	return true, false
}
