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

// Package database defines the Clair's models and a common interface for database implementations.
package database

import (
	"errors"
	"time"
)

var (
	// ErrTransaction is an error that occurs when a database transaction fails.
	// ErrTransaction = errors.New("database: transaction failed (concurrent modification?)")

	// ErrBackendException is an error that occurs when the database backend does
	// not work properly (ie. unreachable).
	ErrBackendException = errors.New("database: an error occured when querying the backend")

	// ErrInconsistent is an error that occurs when a database consistency check
	// fails (ie. when an entity which is supposed to be unique is detected twice)
	ErrInconsistent = errors.New("database: inconsistent database")

	// ErrCantOpen is an error that occurs when the database could not be opened
	ErrCantOpen = errors.New("database: could not open database")
)

type Datastore interface {
	// Namespace
	ListNamespaces() ([]Namespace, error)

	// Layer
	InsertLayer(Layer) error
	FindLayer(name string, withFeatures, withVulnerabilities bool) (Layer, error)
	DeleteLayer(name string) error

	// Vulnerability
	InsertVulnerabilities(vulnerabilities []Vulnerability, createNotification bool) error
	FindVulnerability(namespaceName, name string) (Vulnerability, error)
	DeleteVulnerability(namespaceName, name string) error

	InsertVulnerabilityFixes(vulnerabilityNamespace, vulnerabilityName string, fixes []FeatureVersion) error
	DeleteVulnerabilityFix(vulnerabilityNamespace, vulnerabilityName, featureName string) error

	// Notifications
	GetAvailableNotification(renotifyInterval time.Duration) (VulnerabilityNotification, error) // Does not fill old/new Vulnerabilities.
	GetNotification(name string, limit int, page VulnerabilityNotificationPageNumber) (VulnerabilityNotification, VulnerabilityNotificationPageNumber, error)
	SetNotificationNotified(name string) error
	DeleteNotification(name string) error

	// Key/Value
	InsertKeyValue(key, value string) error
	GetKeyValue(key string) (string, error)

	// Lock
	Lock(name string, owner string, duration time.Duration, renew bool) (bool, time.Time)
	Unlock(name, owner string)
	FindLock(name string) (string, time.Time, error)

	Ping() bool
	Close()
}
