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

// Package namespaces defines an interface for listing the available namespaces, and a few maps between equivalent namespaces.
package namespaces

import (
	"fmt"

	"github.com/coreos/clair/config"
	"github.com/coreos/clair/services"
)

type Driver func(cfg config.RegistrableComponentConfig) (Service, error)

var namespacesDrivers = make(map[string]Driver)

// Register makes a Service constructor available by the provided name.
//
// If this function is called twice with the same name or if the Constructor is
// nil, it panics.
func Register(name string, driver Driver) {
	if driver == nil {
		panic("namespaces: could not register nil Driver")
	}
	if _, dup := namespacesDrivers[name]; dup {
		panic("namespaces: could not register duplicate Driver: " + name)
	}
	namespacesDrivers[name] = driver
}

// Open opens a Datastore specified by a configuration.
func Open(cfg config.RegistrableComponentConfig) (ls Service, err error) {
	driver, ok := namespacesDrivers[cfg.Type]
	if !ok {
		err = fmt.Errorf("namespaces: unknown Driver %q (forgotten configuration or import?)", cfg.Type)
		return
	}
	return driver(cfg)
}

type Service interface {
	services.Base

	// # Namespace
	// ListNamespaces returns the entire list of known Namespaces.
	ListNamespaces() ([]services.Namespace, error)
}
