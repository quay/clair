// Copyright 2019 clair authors
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

// Package stomp implements a notification sender using stomp protocol.
package stomp

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/go-stomp/stomp"
	"github.com/go-stomp/stomp/frame"
	"gopkg.in/yaml.v2"

	"github.com/quay/clair/v3/ext/notification"
	log "github.com/sirupsen/logrus"
)

type Connetion interface {
	Disconnect() error
	Send(destination, contentType string, body []byte, opts ...func(*frame.Frame) error) error
}

type Sender struct {
	Config    Config
	StompConn Connetion
	ConnOpts  []func(*stomp.Conn) error
}

// Config represents the configuration of a Stomp Sender.
type Config struct {
	Brokers            []string
	Destination        string
	CertFile           string
	KeyFile            string
	CAFile             string
	FailoverRetryDelay float32
}

func init() {
	notification.RegisterSender("stomp", &Sender{})
}

// Configure verifies stomp config and sets up stomp connection
func (s *Sender) Configure(config *notification.Config) (bool, error) {
	// Get configuration
	var stompConfig Config
	if config == nil {
		return false, nil
	}
	if _, ok := config.Params["stomp"]; !ok {
		return false, nil
	}
	yamlConfig, err := yaml.Marshal(config.Params["stomp"])
	if err != nil {
		return false, errors.New("invalid configuration")
	}
	err = yaml.Unmarshal(yamlConfig, &stompConfig)
	if err != nil {
		return false, errors.New("invalid configuration")
	}

	// Verify at least one broker is available
	if len(stompConfig.Brokers) == 0 {
		return false, nil
	}
	s.Config = stompConfig
	return true, nil
}

// Connect - connect to one of a brokers which is currently online
func (s *Sender) Connect() error {
	if s.StompConn != nil {
		return nil
	}
	tlsConfig, err := loadTLSClientConfig(&s.Config)
	if err != nil {
		return err
	}

	// try to connect to one of a brokers
	var conn *tls.Conn
	for _, broker := range s.Config.Brokers {
		conn, err = tls.Dial("tcp", broker, tlsConfig)
		if err == nil {
			log.WithField("broker", broker).Info("Established TCP connection to broker")
			break
		}
		log.WithField("broker", broker).Warning("Connection to broker failed")
	}
	if err != nil {
		return err
	}

	// disable heartbeat since it actually just makes us disconnect
	// see: https://github.com/go-stomp/stomp/issues/32
	// remove or set to short time to test failover :-)
	opts := append(s.ConnOpts, stomp.ConnOpt.HeartBeat(0, 0))
	stompConn, err := stomp.Connect(conn, opts...)
	if err != nil {
		return errors.New("Failed stomp connection: " + err.Error())
	}
	s.StompConn = stompConn
	return nil
}

// Disconnect - disconnect from remote broker
func (s *Sender) Disconnect() {
	if s.StompConn != nil {
		s.StompConn.Disconnect()
		s.StompConn = nil
	}
}

type notificationEnvelope struct {
	Notification struct {
		Name string
	}
}

// Send - send notification using STOMP in json format
//
// Send function has failover feature - in case one broker fails it reconnect
// to another broker and send message again
func (s *Sender) Send(notificationName string) error {
	err := s.Connect()
	if err != nil {
		return err
	}
	// Marshal notification.
	jsonNotification, err := json.Marshal(notificationEnvelope{struct{ Name string }{notificationName}})
	if err != nil {
		return fmt.Errorf("could not marshal: %s", err)
	}

	// Send with failover
	opts := []func(*frame.Frame) error{stomp.SendOpt.NoContentLength}
	var retryCount int
	for retryCount = 0; retryCount <= len(s.Config.Brokers); retryCount++ {
		err = s.StompConn.Send(s.Config.Destination, "application/json", jsonNotification, opts...)
		if err == nil {
			break
		}

		if retryCount > 0 {
			log.Debug("Failed send over stomp right after reconnecting. Permission problems?")
		}
		s.Disconnect()

		time.Sleep(time.Duration(s.Config.FailoverRetryDelay*float32(retryCount)) * time.Second)

		err := s.Connect()
		if err != nil {
			log.Error("Failed to connect to any broker during reconnect: " + err.Error())
			return err
		}
	}
	s.Disconnect()

	return nil
}

// loadTLSClientConfig initializes a *tls.Config using the given Config.
//
// If no certificates are given, (nil, nil) is returned.
// The CA certificate is optional and falls back to the system default.
func loadTLSClientConfig(cfg *Config) (*tls.Config, error) {
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
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
	}

	return tlsConfig, nil
}
