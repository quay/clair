// Copyright 2017 The Grafeas Authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package config

import (
	"io/ioutil"

	"github.com/grafeas/grafeas/samples/server/go-server/api/server/server"
	"gopkg.in/yaml.v2"
)

// File is the grafeas config file.
type file struct {
	Grafeas *config `yaml:"grafeas"`
}

// Config is the global configuration for an instance of Grafeas.
type config struct {
	Server *server.Config `yaml:"server"`
}

// DefaultConfig is a configuration that can be used as a fallback value.
func defaultConfig() *config {
	return &config{
		&server.Config{
			Address:  "localhost:10000",
			CertFile: "",
			KeyFile:  "",
			CAFile:   "",
		},
	}
}

// Creates a config from a YAML-file. If fileName is an empty
// string a default config will be returned.
func LoadConfig(fileName string) (*config, error) {
	if fileName == "" {
		return defaultConfig(), nil
	}
	data, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	var configFile file
	err = yaml.Unmarshal(data, &configFile)
	if err != nil {
		return nil, err
	}
	return configFile.Grafeas, nil
}
