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

package clair

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"

	"github.com/quay/clair/v3/pkg/formatter"
	log "github.com/sirupsen/logrus"

	"github.com/tracer0tong/kafkalogrus"
)

// KafkaLoggerConfig stores configuration for Kafka logger
type KafkaLoggerConfig struct {
	Brokers []string
	Topic   string
	Enabled bool
	CACert  string
}

// ConfigureKafkaLogger configures Kafka loggere based on provided config
// When logger is disabled in config it doesn't create Kafka logrus hook
func ConfigureKafkaLogger(kafkaConfig *KafkaLoggerConfig) {
	if kafkaConfig != nil && kafkaConfig.Enabled {
		var hook *kafkalogrus.KafkaLogrusHook
		caCert, err := ioutil.ReadFile(kafkaConfig.CACert)
		if err != nil {
			log.Fatal(err)
			return
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)

		// Setup HTTPS client
		tlsConfig := &tls.Config{
			RootCAs: caCertPool,
		}

		// Create a new hook
		hook, err = kafkalogrus.NewKafkaLogrusHook(
			kafkaConfig.Topic,
			log.AllLevels,
			&formatter.KafkaFormater{ShowLn: true},
			kafkaConfig.Brokers,
			kafkaConfig.Topic,
			false,
			tlsConfig)
		if err != nil {
			log.WithError(err).Error("failed to set Kafka logger")
		}
		log.AddHook(hook)
	}
}
