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
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"time"

	"github.com/coreos/pkg/capnslog"
	"github.com/pborman/uuid"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/health"
	"github.com/coreos/clair/utils"
	httputils "github.com/coreos/clair/utils/http"
)

var log = capnslog.NewPackageLogger("github.com/coreos/clair", "notifier")

const (
	checkInterval = 5 * time.Minute

	refreshLockDuration = time.Minute * 2
	lockDuration        = time.Minute*8 + refreshLockDuration
)

// A Notification represents the structure of the notifications that are sent by a Notifier.
type Notification struct {
	Name, Type string
	Content    interface{}
}

// A Notifier dispatches notifications to an HTTP endpoint.
type Notifier struct {
	lockIdentifier string
	endpoint       string
	client         *http.Client
}

// Config represents the configuration of a Notifier.
// The certificates are optionnal and enable client certificate authentification.
type Config struct {
	Endpoint                  string
	CertFile, KeyFile, CAFile string
}

// New initializes a new Notifier from the specified configuration.
func New(cfg Config) *Notifier {
	if _, err := url.Parse(cfg.Endpoint); err != nil {
		log.Fatal("could not create a notifier with an invalid endpoint URL")
	}

	// Initialize TLS
	tlsConfig, err := httputils.LoadTLSClientConfig(cfg.CertFile, cfg.KeyFile, cfg.CAFile)
	if err != nil {
		log.Fatalf("could not initialize client cert authentification: %s\n", err)
	}
	if tlsConfig != nil {
		log.Info("notifier configured with client certificate authentification")
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	return &Notifier{
		lockIdentifier: uuid.New(),
		endpoint:       cfg.Endpoint,
		client:         httpClient,
	}
}

// Serve starts the Notifier.
func (n *Notifier) Serve(stopper *utils.Stopper) {
	defer stopper.End()
	health.RegisterHealthchecker("notifier", n.Healthcheck)

	log.Infof("notifier service started. endpoint: %s. lock identifier: %s\n", n.endpoint, n.lockIdentifier)

	for {
		// Find task.
		// TODO(Quentin-M): Combine node and notification.
		node, notification := n.findTask(stopper)
		if node == "" && notification == nil {
			break
		}

		// Handle task.
		done := make(chan bool, 1)
		go func() {
			if n.handleTask(node, notification) {
				database.MarkNotificationAsSent(node)
			}
			database.Unlock(node, n.lockIdentifier)
			done <- true
		}()

		// Refresh task lock until done.
	outer:
		for {
			select {
			case <-done:
				break outer
			case <-time.After(refreshLockDuration):
				database.Lock(node, lockDuration, n.lockIdentifier)
			}
		}
	}

	log.Info("notifier service stopped")
}

func (n *Notifier) findTask(stopper *utils.Stopper) (string, database.Notification) {
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
		if hasLock, _ := database.Lock(node, lockDuration, n.lockIdentifier); hasLock {
			log.Infof("found and locked a notification: %s", notification.GetName())
			return node, notification
		}
	}
}

func (n *Notifier) handleTask(node string, notification database.Notification) bool {
	// Get notification content.
	// TODO(Quentin-M): Split big notifications.
	notificationContent, err := notification.GetContent()
	if err != nil {
		log.Warningf("could not get content of notification '%s': %s", notification.GetName(), err)
		return false
	}

	// Create notification.
	payload := Notification{
		Name:    notification.GetName(),
		Type:    notification.GetType(),
		Content: notificationContent,
	}

	// Marshal notification.
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		log.Errorf("could not marshal content of notification '%s': %s", notification.GetName(), err)
		return false
	}

	// Send notification.
	resp, err := n.client.Post(n.endpoint, "application/json", bytes.NewBuffer(jsonPayload))
	defer resp.Body.Close()
	if err != nil || (resp.StatusCode != 200 && resp.StatusCode != 201) {
		log.Errorf("could not send notification '%s': (%d) %s", notification.GetName(), resp.StatusCode, err)
		return false
	}

	log.Infof("successfully sent notification '%s'\n", notification.GetName())
	return true
}

// Healthcheck returns the health of the notifier service.
func (n *Notifier) Healthcheck() health.Status {
	queueSize, err := database.CountNotificationsToSend()
	return health.Status{IsEssential: false, IsHealthy: err == nil, Details: struct{ QueueSize int }{QueueSize: queueSize}}
}
