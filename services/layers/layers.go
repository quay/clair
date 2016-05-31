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

// Package layers defines an interface for reading and writing layer metadata.
package layers

import (
	"fmt"

	"github.com/coreos/clair/config"
	"github.com/coreos/clair/services"
)

type Driver func(cfg config.RegistrableComponentConfig) (Service, error)

var layerDrivers = make(map[string]Driver)

// Register makes a Layer constructor available by the provided name.
//
// If this function is called twice with the same name or if the Constructor is
// nil, it panics.
func Register(name string, driver Driver) {
	if driver == nil {
		panic("layers: could not register nil Driver")
	}
	if _, dup := layerDrivers[name]; dup {
		panic("layers: could not register duplicate Driver: " + name)
	}
	layerDrivers[name] = driver
}

// Open opens a Datastore specified by a configuration.
func Open(cfg config.RegistrableComponentConfig) (ls Service, err error) {
	driver, ok := layerDrivers[cfg.Type]
	if !ok {
		err = fmt.Errorf("layers: unknown Driver %q (forgotten configuration or import?)", cfg.Type)
		return
	}
	return driver(cfg)
}

type Service interface {
	services.Base
	// # Layer
	// InsertLayer stores a Layer in the database.
	// A Layer is uniquely identified by its Name. The Name and EngineVersion fields are mandatory.
	// If a Parent is specified, it is expected that it has been retrieved using FindLayer.
	// If a Layer that already exists is inserted and the EngineVersion of the given Layer is higher
	// than the stored one, the stored Layer should be updated.
	// The function has to be idempotent, inserting a layer that already exists shouln'd return an
	// error.
	InsertLayer(services.Layer) error

	// FindLayer retrieves a Layer from the database.
	// withFeatures specifies whether the Features field should be filled. When withVulnerabilities is
	// true, the Features field should be filled and their AffectedBy fields should contain every
	// vulnerabilities that affect them.
	FindLayer(name string, withFeatures, withVulnerabilities bool) (services.Layer, error)

	// DeleteLayer deletes a Layer from the database and every layers that are based on it,
	// recursively.
	DeleteLayer(name string) error
}
