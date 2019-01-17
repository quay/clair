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

// Package messagebus implements a notification sender for activemq.
package messagebus

import (
	"errors"

	"gopkg.in/yaml.v2"

	"github.com/coreos/clair/ext/notification"
	messsagebus "gitlab.cee.redhat.com/rad/go-umb"
)

type sender struct {
	Messagebus  *messsagebus.UMBConnection
	Destination string
}

// Config represents the configuration of a Messagebus Sender.
type Config struct {
	Brokers     []string
	CertFile    string
	KeyFile     string
	CAFile      string
	Destination string
}

func init() {
	notification.RegisterSender("messagebus", &sender{})
}

func (s *sender) Configure(config *notification.Config) (bool, error) {
	// Get configuration
	var messageBusConfig Config
	if config == nil {
		return false, nil
	}
	if _, ok := config.Params["messsagebus"]; !ok {
		return false, nil
	}
	yamlConfig, err := yaml.Marshal(config.Params["messsagebus"])
	if err != nil {
		return false, errors.New("invalid configuration")
	}
	err = yaml.Unmarshal(yamlConfig, &messageBusConfig)
	if err != nil {
		return false, errors.New("invalid configuration")
	}

	// Validate brokers
	if len(messageBusConfig.Brokers) == 0 {
		return false, nil
	}
	s.Messagebus = messsagebus.NewUMBConnection(
		messageBusConfig.CertFile,
		messageBusConfig.KeyFile,
		messageBusConfig.CAFile,
		messageBusConfig.Brokers,
	)
	s.Destination = messageBusConfig.Destination
	err = s.Messagebus.Connect()
	if err != nil {
		return false, err
	}
	return true, nil
}

type notificationEnvelope struct {
	Notification struct {
		Name string
	}
}

func (s *sender) Send(notificationName string) error {
	notification := notificationEnvelope{
		struct{ Name string }{notificationName}}

	// send notification via MessageBus
	err := s.Messagebus.FailoverSend(
		s.Destination,
		notification,
	)
	if err != nil {
		return err
	}

	return nil
}
