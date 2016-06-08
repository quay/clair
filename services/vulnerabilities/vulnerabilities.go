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

// Package vulnerabilities defines an interface for listing, reading and writing vulnerability information
package vulnerabilities

import (
	"fmt"

	"github.com/coreos/clair/config"
	"github.com/coreos/clair/services"
)

type Driver func(cfg config.RegistrableComponentConfig) (Service, error)

var vulnzDrivers = make(map[string]Driver)

// Register makes a Vulnerability constructor available by the provided name.
//
// If this function is called twice with the same name or if the Constructor is
// nil, it panics.
func Register(name string, driver Driver) {
	if driver == nil {
		panic("vulnerabilities: could not register nil Driver")
	}
	if _, dup := vulnzDrivers[name]; dup {
		panic("vulnerabilities: could not register duplicate Driver: " + name)
	}
	vulnzDrivers[name] = driver
}

// Open opens a Datastore specified by a configuration.
func Open(cfg config.RegistrableComponentConfig) (ls Service, err error) {
	driver, ok := vulnzDrivers[cfg.Type]
	if !ok {
		err = fmt.Errorf("vulnerabilities: unknown Driver %q (forgotten configuration or import?)", cfg.Type)
		return
	}
	return driver(cfg)
}

type Service interface {
	services.Base

	// # Namespace
	// ListNamespaces returns the entire list of known Namespaces.
	ListNamespaces() ([]services.Namespace, error)

	// # Vulnerability
	// ListVulnerabilities returns the list of vulnerabilies of a certain Namespace.
	// The Limit and page parameters are used to paginate the return list.
	// The first given page should be 0. The function will then return the next available page.
	// If there is no more page, -1 has to be returned.
	ListVulnerabilities(namespaceName string, limit int, page int) ([]services.Vulnerability, int, error)
	// InsertVulnerabilities stores the given Vulnerabilities in the database, updating them if
	// necessary. A vulnerability is uniquely identified by its Namespace and its Name.
	// The FixedIn field may only contain a partial list of Features that are affected by the
	// Vulnerability, along with the version in which the vulnerability is fixed. It is the
	// responsibility of the implementation to update the list properly. A version equals to
	// types.MinVersion means that the given Feature is not being affected by the Vulnerability at
	// all and thus, should be removed from the list. It is important that Features should be unique
	// in the FixedIn list. For example, it doesn't make sense to have two `openssl` Feature listed as
	// a Vulnerability can only be fixed in one Version. This is true because Vulnerabilities and
	// Features are Namespaced (i.e. specific to one operating system).
	// Each vulnerability insertion or update has to create a Notification that will contain the
	// old and the updated Vulnerability, unless createNotification equals to true.
	InsertVulnerabilities(vulnerabilities []services.Vulnerability, createNotification bool) error
	// FindVulnerability retrieves a Vulnerability from the database, including the FixedIn list.
	FindVulnerability(namespaceName, name string) (services.Vulnerability, error)
	// DeleteVulnerability removes a Vulnerability from the database.
	// It has to create a Notification that will contain the old Vulnerability.
	DeleteVulnerability(namespaceName, name string) error
	// InsertVulnerabilityFixes adds new FixedIn Feature or update the Versions of existing ones to
	// the specified Vulnerability in the database.
	// It has has to create a Notification that will contain the old and the updated Vulnerability.
	InsertVulnerabilityFixes(vulnerabilityNamespace, vulnerabilityName string, fixes []services.FeatureVersion) error
	// DeleteVulnerabilityFix removes a FixedIn Feature from the specified Vulnerability in the
	// database. It can be used to store the fact that a Vulnerability no longer affects the given
	// Feature in any Version.
	// It has has to create a Notification that will contain the old and the updated Vulnerability.
	DeleteVulnerabilityFix(vulnerabilityNamespace, vulnerabilityName, featureName string) error

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
