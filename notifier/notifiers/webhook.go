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

// Package notifiers implements several kinds of notifier.Notifier
package notifiers

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"gopkg.in/yaml.v2"

	"github.com/coreos/clair/config"
	"github.com/coreos/clair/notifier"
)

// A WebhookNotifier dispatches notifications to a webhook endpoint.
type WebhookNotifier struct {
	endpoint string
	client   *http.Client
}

// A WebhookNotifierConfiguration represents the configuration of a WebhookNotifier.
type WebhookNotifierConfiguration struct {
	Endpoint   string
	ServerName string
	CertFile   string
	KeyFile    string
	CAFile     string
}

func init() {
	notifier.RegisterNotifier("webhook", &WebhookNotifier{})
}

func (h *WebhookNotifier) Configure(config *config.NotifierConfig) (bool, error) {
	// Get configuration
	var httpConfig WebhookNotifierConfiguration
	if config == nil {
		return false, nil
	}
	if _, ok := config.Params["http"]; !ok {
		return false, nil
	}
	yamlConfig, err := yaml.Marshal(config.Params["http"])
	if err != nil {
		return false, errors.New("invalid configuration")
	}
	err = yaml.Unmarshal(yamlConfig, &httpConfig)
	if err != nil {
		return false, errors.New("invalid configuration")
	}

	// Validate endpoint URL.
	if httpConfig.Endpoint == "" {
		return false, nil
	}
	if _, err := url.Parse(httpConfig.Endpoint); err != nil {
		return false, errors.New("invalid endpoint URL")
	}
	h.endpoint = httpConfig.Endpoint

	// Initialize TLS.
	tlsConfig, err := loadTLSClientConfig(&httpConfig)
	if err != nil {
		return false, fmt.Errorf("could not initialize client cert auth: %s\n", err)
	}

	h.client = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}
	return true, nil
}

func (h *WebhookNotifier) Send(notification *notifier.Notification) error {
	// Marshal notification.
	jsonNotification, err := json.Marshal(notification)
	if err != nil {
		return fmt.Errorf("could not marshal: %s", err)
	}

	// Send notification via HTTP POST.
	resp, err := h.client.Post(h.endpoint, "application/json", bytes.NewBuffer(jsonNotification))
	if err != nil || resp == nil || (resp.StatusCode != 200 && resp.StatusCode != 201) {
		if resp != nil {
			return fmt.Errorf("(%d) %s", resp.StatusCode, err)
		}
		return err
	}
	defer resp.Body.Close()

	return nil
}

// loadTLSClientConfig initializes a *tls.Config using the given WebhookNotifierConfiguration.
//
// If no certificates are given, (nil, nil) is returned.
// The CA certificate is optional and falls back to the system default.
func loadTLSClientConfig(cfg *WebhookNotifierConfiguration) (*tls.Config, error) {
	if cfg.CertFile == "" || cfg.KeyFile == "" {
		return nil, nil
	}

	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, err
	}

	var caCertPool *x509.CertPool
	if cfg.CAFile != "" {
		caCert, err := ioutil.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, err
		}
		caCertPool = x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
	}

	tlsConfig := &tls.Config{
		ServerName:   cfg.ServerName,
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
	}

	return tlsConfig, nil
}
