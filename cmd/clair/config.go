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

package main

import (
	"errors"
	"io/ioutil"
	"os"
	"time"

	"github.com/fernet/fernet-go"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"

	"github.com/coreos/clair"
	"github.com/coreos/clair/api"
	"github.com/coreos/clair/database"
	"github.com/coreos/clair/ext/featurefmt"
	"github.com/coreos/clair/ext/featurens"
	"github.com/coreos/clair/ext/notification"
	"github.com/coreos/clair/ext/vulnsrc"
	"github.com/coreos/clair/grafeas"
)

// ErrDatasourceNotLoaded is returned when the datasource variable in the
// configuration file is not loaded properly
var ErrDatasourceNotLoaded = errors.New("could not load configuration: no database source specified")

// File represents a YAML configuration file that namespaces all Clair
// configuration under the top-level "clair" key.
type File struct {
	Clair Config `yaml:"clair"`
}

// Config is the global configuration for an instance of Clair.
type Config struct {
	Database database.RegistrableComponentConfig
	Updater  *clair.UpdaterConfig
	Worker   *clair.WorkerConfig
	Notifier *notification.Config
	API      *api.Config
	Grafeas  *grafeas.Config
}

// DefaultConfig is a configuration that can be used as a fallback value.
func DefaultConfig() Config {
	return Config{
		Database: database.RegistrableComponentConfig{
			Type: "pgsql",
		},
		Updater: &clair.UpdaterConfig{
			EnabledUpdaters: vulnsrc.ListUpdaters(),
			Interval:        1 * time.Hour,
		},
		Worker: &clair.WorkerConfig{
			EnabledDetectors: featurens.ListDetectors(),
			EnabledListers:   featurefmt.ListListers(),
		},
		API: &api.Config{
			HealthAddr: "0.0.0.0:6061",
			Addr:       "0.0.0.0:6060",
			Timeout:    900 * time.Second,
		},
		Notifier: &notification.Config{
			Attempts:         5,
			RenotifyInterval: 2 * time.Hour,
		},
		Grafeas: &grafeas.Config{
			Enabled:   false,
			Addr:      "0.0.0.0:8080",
			ProjectId: "vuln-scanner",
		},
	}
}

// LoadConfig is a shortcut to open a file, read it, and generate a Config.
//
// It supports relative and absolute paths. Given "", it returns DefaultConfig.
func LoadConfig(path string) (config *Config, err error) {
	var cfgFile File
	cfgFile.Clair = DefaultConfig()
	if path == "" {
		return &cfgFile.Clair, nil
	}

	f, err := os.Open(os.ExpandEnv(path))
	if err != nil {
		return
	}
	defer f.Close()

	d, err := ioutil.ReadAll(f)
	if err != nil {
		return
	}

	err = yaml.Unmarshal(d, &cfgFile)
	if err != nil {
		return
	}
	config = &cfgFile.Clair

	// Generate a pagination key if none is provided.
	if v, ok := config.Database.Options["paginationkey"]; !ok || v == nil || v.(string) == "" {
		log.Warn("pagination key is empty, generating...")
		var key fernet.Key
		if err = key.Generate(); err != nil {
			return
		}
		config.Database.Options["paginationkey"] = key.Encode()
	} else {
		_, err = fernet.DecodeKey(config.Database.Options["paginationkey"].(string))
		if err != nil {
			err = errors.New("Invalid Pagination key; must be 32-bit URL-safe base64")
			return
		}
	}

	return
}
