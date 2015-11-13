// Copyright 2015 quay-sec authors
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
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"time"

	"github.com/coreos/pkg/capnslog"
	"github.com/coreos/pkg/timeutil"
	"github.com/coreos/quay-sec/database"
	cerrors "github.com/coreos/quay-sec/utils/errors"
	"github.com/coreos/quay-sec/health"
	"github.com/coreos/quay-sec/utils"
	"github.com/pborman/uuid"
)

// A Notifier dispatches notifications
type Notifier interface {
	Run(*utils.Stopper)
}

var log = capnslog.NewPackageLogger("github.com/coreos/quay-sec", "notifier")

const (
	maxBackOff    = 5 * time.Minute
	checkInterval = 5 * time.Second

	refreshLockAnticipation = time.Minute * 2
	lockDuration            = time.Minute*8 + refreshLockAnticipation
)

// A HTTPNotifier dispatches notifications to an HTTP endpoint with POST requests
type HTTPNotifier struct {
	url string
}

// NewHTTPNotifier initializes a new HTTPNotifier
func NewHTTPNotifier(URL string) (*HTTPNotifier, error) {
	if _, err := url.Parse(URL); err != nil {
		return nil, cerrors.NewBadRequestError("could not create a notifier with an invalid URL")
	}

	notifier := &HTTPNotifier{url: URL}
	health.RegisterHealthchecker("notifier", notifier.Healthcheck)

	return notifier, nil
}

// Run pops notifications from the database, lock them, send them, mark them as
// send and unlock them
//
// It uses an exponential backoff when POST requests fail
func (notifier *HTTPNotifier) Run(st *utils.Stopper) {
	defer st.End()

	whoAmI := uuid.New()
	log.Infof("HTTP notifier started. URL: %s. Lock Identifier: %s", notifier.url, whoAmI)

	for {
		node, notification, err := database.FindOneNotificationToSend(database.GetDefaultNotificationWrapper())
		if notification == nil || err != nil {
			if err != nil {
				log.Warningf("could not get notification to send: %s.", err)
			}

			if !st.Sleep(checkInterval) {
				break
			}

			continue
		}

		// Try to lock the notification
		hasLock, hasLockUntil := database.Lock(node, lockDuration, whoAmI)
		if !hasLock {
			continue
		}

		for backOff := time.Duration(0); ; backOff = timeutil.ExpBackoff(backOff, maxBackOff) {
			// Backoff, it happens when an error occurs during the communication
			// with the notification endpoint
			if backOff > 0 {
				// Renew lock before going to sleep if necessary
				if time.Now().Add(backOff).After(hasLockUntil.Add(-refreshLockAnticipation)) {
					hasLock, hasLockUntil = database.Lock(node, lockDuration, whoAmI)
					if !hasLock {
						log.Warning("lost lock ownership, aborting")
						break
					}
				}

				// Sleep
				if !st.Sleep(backOff) {
					return
				}
			}

			// Get notification content
			content, err := notification.GetContent()
			if err != nil {
				log.Warningf("could not get content of notification '%s': %s", notification.GetName(), err.Error())
				break
			}

			// Marshal the notification content
			jsonContent, err := json.Marshal(struct {
				Name, Type string
				Content    interface{}
			}{
				Name:    notification.GetName(),
				Type:    notification.GetType(),
				Content: content,
			})
			if err != nil {
				log.Errorf("could not marshal content of notification '%s': %s", notification.GetName(), err.Error())
				break
			}

			// Post notification
			req, _ := http.NewRequest("POST", notifier.url, bytes.NewBuffer(jsonContent))
			req.Header.Set("Content-Type", "application/json")

			client := &http.Client{}
			res, err := client.Do(req)
			if err != nil {
				log.Warningf("could not post notification '%s': %s", notification.GetName(), err.Error())
				continue
			}
			res.Body.Close()

			if res.StatusCode != 200 && res.StatusCode != 201 {
				log.Warningf("could not post notification '%s': got status code %d", notification.GetName(), res.StatusCode)
				continue
			}

			// Mark the notification as sent
			database.MarkNotificationAsSent(node)

			log.Infof("sent notification '%s' successfully", notification.GetName())
			break
		}

		if hasLock {
			database.Unlock(node, whoAmI)
		}
	}

	log.Info("HTTP notifier stopped")
}

// Healthcheck returns the health of the notifier service
func (notifier *HTTPNotifier) Healthcheck() health.Status {
	queueSize, err := database.CountNotificationsToSend()
	return health.Status{IsEssential: false, IsHealthy: err == nil, Details: struct{ QueueSize int }{QueueSize: queueSize}}
}
