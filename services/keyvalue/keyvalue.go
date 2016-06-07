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

// Package keyvalue defines an interface for a simple keyvalue store.
package keyvalue

import (
	"fmt"

	"github.com/coreos/clair/config"
	"github.com/coreos/clair/services"
)

type Driver func(cfg config.RegistrableComponentConfig) (Service, error)

var keyValueDrivers = make(map[string]Driver)

// Register makes a Service constructor available by the provided name.
//
// If this function is called twice with the same name or if the Constructor is
// nil, it panics.
func Register(name string, driver Driver) {
	if driver == nil {
		panic("keyvalue: could not register nil Driver")
	}
	if _, dup := keyValueDrivers[name]; dup {
		panic("keyvalue: could not register duplicate Driver: " + name)
	}
	keyValueDrivers[name] = driver
}

// Open opens a Datastore specified by a configuration.
func Open(cfg config.RegistrableComponentConfig) (ls Service, err error) {
	driver, ok := keyValueDrivers[cfg.Type]
	if !ok {
		err = fmt.Errorf("keyvalue: unknown Driver %q (forgotten configuration or import?)", cfg.Type)
		return
	}
	return driver(cfg)
}

type Service interface {
	services.Base
	// # Key/Value
	// InsertKeyValue stores or updates a simple key/value pair in the database.
	InsertKeyValue(key, value string) error
	// GetKeyValue retrieves a value from the database from the given key.
	// It returns an empty string if there is no such key.
	GetKeyValue(key string) (string, error)
}
