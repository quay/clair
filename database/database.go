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

// Package database defines the Clair's models and a common interface for
// database implementations.
package database

import (
	"errors"
	"fmt"
	"time"
)

var (
	// ErrBackendException is an error that occurs when the database backend
	// does not work properly (ie. unreachable).
	ErrBackendException = errors.New("database: an error occurred when querying the backend")

	// ErrInconsistent is an error that occurs when a database consistency check
	// fails (i.e. when an entity which is supposed to be unique is detected
	// twice)
	ErrInconsistent = errors.New("database: inconsistent database")
)

// RegistrableComponentConfig is a configuration block that can be used to
// determine which registrable component should be initialized and pass custom
// configuration to it.
type RegistrableComponentConfig struct {
	Type    string
	Options map[string]interface{}
}

var drivers = make(map[string]Driver)

// Driver is a function that opens a Datastore specified by its database driver
// type and specific configuration.
type Driver func(RegistrableComponentConfig) (Datastore, error)

// Register makes a Constructor available by the provided name.
//
// If this function is called twice with the same name or if the Constructor is
// nil, it panics.
func Register(name string, driver Driver) {
	if driver == nil {
		panic("database: could not register nil Driver")
	}
	if _, dup := drivers[name]; dup {
		panic("database: could not register duplicate Driver: " + name)
	}
	drivers[name] = driver
}

// Open opens a Datastore specified by a configuration.
func Open(cfg RegistrableComponentConfig) (Datastore, error) {
	driver, ok := drivers[cfg.Type]
	if !ok {
		return nil, fmt.Errorf("database: unknown Driver %q (forgotten configuration or import?)", cfg.Type)
	}
	return driver(cfg)
}

// Session contains the required operations on a persistent data store for a
// Clair deployment.
//
// Session is started by Datastore.Begin and terminated with Commit or Rollback.
// Besides Commit and Rollback, other functions cannot be called after the
// session is terminated.
// Any function is not guaranteed to be called successfully if there's a session
// failure.
type Session interface {
	// Commit commits changes to datastore.
	//
	// Commit call after Rollback does no-op.
	Commit() error

	// Rollback drops changes to datastore.
	//
	// Rollback call after Commit does no-op.
	Rollback() error

	// UpsertAncestry inserts or replaces an ancestry and its namespaced
	// features and processors used to scan the ancestry.
	UpsertAncestry(ancestry Ancestry, features []NamespacedFeature, processedBy Processors) error

	// FindAncestry retrieves an ancestry with processors used to scan the
	// ancestry. If the ancestry is not found, return false.
	//
	// The ancestry's processors are returned to short cut processing ancestry
	// if it has been processed by all processors in the current Clair instance.
	FindAncestry(name string) (ancestry Ancestry, processedBy Processors, found bool, err error)

	// FindAncestryFeatures retrieves an ancestry with all detected namespaced
	// features. If the ancestry is not found, return false.
	FindAncestryFeatures(name string) (ancestry AncestryWithFeatures, found bool, err error)

	// PersistFeatures inserts a set of features if not in the database.
	PersistFeatures(features []Feature) error

	// PersistNamespacedFeatures inserts a set of namespaced features if not in
	// the database.
	PersistNamespacedFeatures([]NamespacedFeature) error

	// CacheAffectedNamespacedFeatures relates the namespaced features with the
	// vulnerabilities affecting these features.
	//
	// NOTE(Sida): it's not necessary for every database implementation and so
	// this function may have a better home.
	CacheAffectedNamespacedFeatures([]NamespacedFeature) error

	// FindAffectedNamespacedFeatures retrieves a set of namespaced features
	// with affecting vulnerabilities.
	FindAffectedNamespacedFeatures(features []NamespacedFeature) ([]NullableAffectedNamespacedFeature, error)

	// PersistNamespaces inserts a set of namespaces if not in the database.
	PersistNamespaces([]Namespace) error

	// PersistLayer inserts a layer if not in the datastore.
	PersistLayer(Layer) error

	// PersistLayerContent persists a layer's content in the database. The given
	// namespaces and features can be partial content of this layer.
	//
	// The layer, namespaces and features are expected to be already existing
	// in the database.
	PersistLayerContent(hash string, namespaces []Namespace, features []Feature, processedBy Processors) error

	// FindLayer retrieves a layer and the processors scanned the layer.
	FindLayer(hash string) (layer Layer, processedBy Processors, found bool, err error)

	// FindLayerWithContent returns a layer with all detected features and
	// namespaces.
	FindLayerWithContent(hash string) (layer LayerWithContent, found bool, err error)

	// InsertVulnerabilities inserts a set of UNIQUE vulnerabilities with
	// affected features into database, assuming that all vulnerabilities
	// provided are NOT in database and all vulnerabilities' namespaces are
	// already in the database.
	InsertVulnerabilities([]VulnerabilityWithAffected) error

	// FindVulnerability retrieves a set of Vulnerabilities with affected
	// features.
	FindVulnerabilities([]VulnerabilityID) ([]NullableVulnerability, error)

	// DeleteVulnerability removes a set of Vulnerabilities assuming that the
	// requested vulnerabilities are in the database.
	DeleteVulnerabilities([]VulnerabilityID) error

	// InsertVulnerabilityNotifications inserts a set of unique vulnerability
	// notifications into datastore, assuming that they are not in the database.
	InsertVulnerabilityNotifications([]VulnerabilityNotification) error

	// FindNewNotification retrieves a notification, which has never been
	// notified or notified before a certain time.
	FindNewNotification(notifiedBefore time.Time) (hook NotificationHook, found bool, err error)

	// FindVulnerabilityNotification retrieves a vulnerability notification with
	// affected ancestries affected by old or new vulnerability.
	//
	// Because the number of affected ancestries maybe large, they are paginated
	// and their pages are specified by the given encrypted PageNumbers, which,
	// if empty, are always considered first page.
	//
	// Session interface implementation should have encrypt and decrypt
	// functions for PageNumber.
	FindVulnerabilityNotification(name string, limit int,
		oldVulnerabilityPage PageNumber,
		newVulnerabilityPage PageNumber) (
		noti VulnerabilityNotificationWithVulnerable,
		found bool, err error)

	// MarkNotificationNotified marks a Notification as notified now, assuming
	// the requested notification is in the database.
	MarkNotificationNotified(name string) error

	// DeleteNotification removes a Notification in the database.
	DeleteNotification(name string) error

	// UpdateKeyValue stores or updates a simple key/value pair.
	UpdateKeyValue(key, value string) error

	// FindKeyValue retrieves a value from the given key.
	FindKeyValue(key string) (value string, found bool, err error)

	// Lock creates or renew a Lock in the database with the given name, owner
	// and duration.
	//
	// After the specified duration, the Lock expires by itself if it hasn't been
	// unlocked, and thus, let other users create a Lock with the same name.
	// However, the owner can renew its Lock by setting renew to true.
	// Lock should not block, it should instead returns whether the Lock has been
	// successfully acquired/renewed. If it's the case, the expiration time of
	// that Lock is returned as well.
	Lock(name string, owner string, duration time.Duration, renew bool) (success bool, expiration time.Time, err error)

	// Unlock releases an existing Lock.
	Unlock(name, owner string) error

	// FindLock returns the owner of a Lock specified by the name, and its
	// expiration time if it exists.
	FindLock(name string) (owner string, expiration time.Time, found bool, err error)
}

// Datastore represents a persistent data store
type Datastore interface {
	// Begin starts a session to change.
	Begin() (Session, error)

	// Ping returns the health status of the database.
	Ping() bool

	// Close closes the database and frees any allocated resource.
	Close()
}
