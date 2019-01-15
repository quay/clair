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

// Package webhook implements a notification sender for HTTP JSON webhooks.
package webhook

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
	"time"

	"gopkg.in/yaml.v2"

	"github.com/coreos/clair/ext/notification"
)

const timeout = 5 * time.Second

type sender struct {
	endpoint string
	token    string
	client   *http.Client
}

// Config represents the configuration of a Webhook Sender.
type Config struct {
	Endpoint   string
	ServerName string
	CertFile   string
	KeyFile    string
	CAFile     string

	TokenFile string
	Token     string

	Proxy string
}

func init() {
	notification.RegisterSender("webhook", &sender{})
}

func (s *sender) Configure(config *notification.Config) (bool, error) {
	// Get configuration
	var httpConfig Config
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
	var webhookURL *url.URL
	if webhookURL, err = url.ParseRequestURI(httpConfig.Endpoint); err != nil {
		return false, fmt.Errorf("could not parse endpoint URL: %s\n", err)
	}
	s.endpoint = httpConfig.Endpoint

	// get the auth token
	if httpConfig.Token != "" {
		s.token = httpConfig.Token
	} else if httpConfig.TokenFile != "" {
		byteToken, err := ioutil.ReadFile(httpConfig.TokenFile)
		if err != nil {
			return false, err
		}
		s.token = string(byteToken)
	}

	// Setup HTTP client.
	transport := &http.Transport{}
	s.client = &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}

	// Initialize TLS only if the scheme is 'https'.
	if webhookURL.Scheme == "https" {
		transport.TLSClientConfig, err = loadTLSClientConfig(&httpConfig)
		if err != nil {
			return false, fmt.Errorf("could not initialize client cert auth: %s\n", err)
		}
	}

	// Set proxy.
	if httpConfig.Proxy != "" {
		proxyURL, err := url.ParseRequestURI(httpConfig.Proxy)
		if err != nil {
			return false, fmt.Errorf("could not parse proxy URL: %s\n", err)
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}

	return true, nil
}

type notificationEnvelope struct {
	Notification struct {
		Name string
	}
}

func (s *sender) Send(notificationName string) error {
	// Marshal notification.
	jsonNotification, err := json.Marshal(notificationEnvelope{struct{ Name string }{notificationName}})
	if err != nil {
		return fmt.Errorf("could not marshal: %s", err)
	}

	// Send notification via HTTP POST.
	req, err := http.NewRequest("POST", s.endpoint, bytes.NewBuffer(jsonNotification))
	if err != nil {
		return fmt.Errorf("failed to create new post request to send notification with name %q", notificationName)
	}
	req.Header.Set("Content-Type", "application/json")
	if s.token != "" {
		req.Header.Set("Authorization", "Bearer "+s.token)
	}
	resp, err := s.client.Do(req)
	if err != nil || resp == nil || (resp.StatusCode != 200 && resp.StatusCode != 201) {
		if resp != nil {
			return fmt.Errorf("got status %d, expected 200/201", resp.StatusCode)
		}
		return err
	}
	defer resp.Body.Close()

	return nil
}

// loadTLSClientConfig initializes a *tls.Config using the given Config.
//
// If no certificates are given, (nil, nil) is returned.
// The CA certificate is optional and falls back to the system default.
func loadTLSClientConfig(cfg *Config) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		ServerName: cfg.ServerName,
	}

	var caCertPool *x509.CertPool
	if cfg.CAFile != "" {
		caCert, err := ioutil.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, err
		}
		caCertPool = x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)

		tlsConfig.RootCAs = caCertPool
	}

	if cfg.CertFile != "" && cfg.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, err
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	return tlsConfig, nil
}
