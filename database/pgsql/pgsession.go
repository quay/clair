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

package pgsql

import (
	"database/sql"
	"time"

	"github.com/coreos/clair/database/pgsql/keyvalue"
	"github.com/coreos/clair/database/pgsql/vulnerability"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/database/pgsql/ancestry"
	"github.com/coreos/clair/database/pgsql/detector"
	"github.com/coreos/clair/database/pgsql/feature"
	"github.com/coreos/clair/database/pgsql/layer"
	"github.com/coreos/clair/database/pgsql/lock"
	"github.com/coreos/clair/database/pgsql/namespace"
	"github.com/coreos/clair/database/pgsql/notification"
	"github.com/coreos/clair/pkg/pagination"
)

type pgSession struct {
	*sql.Tx

	key pagination.Key
}

func (tx *pgSession) Commit() error {
	return tx.Tx.Commit()
}

// Rollback drops changes to datastore.
//
// Rollback call after Commit does no-op.
func (tx *pgSession) Rollback() error {
	return tx.Tx.Rollback()
}

// UpsertAncestry inserts or replaces an ancestry and its namespaced
// features and processors used to scan the ancestry.
func (tx *pgSession) UpsertAncestry(a database.Ancestry) error {
	return ancestry.UpsertAncestry(tx.Tx, a)
}

// FindAncestry retrieves an ancestry with all detected
// namespaced features. If the ancestry is not found, return false.
func (tx *pgSession) FindAncestry(name string) (database.Ancestry, bool, error) {
	return ancestry.FindAncestry(tx.Tx, name)
}

// PersistDetector inserts a slice of detectors if not in the database.
func (tx *pgSession) PersistDetectors(detectors []database.Detector) error {
	return detector.PersistDetectors(tx.Tx, detectors)
}

// PersistFeatures inserts a set of features if not in the database.
func (tx *pgSession) PersistFeatures(features []database.Feature) error {
	return feature.PersistFeatures(tx.Tx, features)
}

// PersistNamespacedFeatures inserts a set of namespaced features if not in
// the database.
func (tx *pgSession) PersistNamespacedFeatures(features []database.NamespacedFeature) error {
	return feature.PersistNamespacedFeatures(tx.Tx, features)
}

// CacheAffectedNamespacedFeatures relates the namespaced features with the
// vulnerabilities affecting these features.
//
// NOTE(Sida): it's not necessary for every database implementation and so
// this function may have a better home.
func (tx *pgSession) CacheAffectedNamespacedFeatures(features []database.NamespacedFeature) error {
	return vulnerability.CacheAffectedNamespacedFeatures(tx.Tx, features)
}

// FindAffectedNamespacedFeatures retrieves a set of namespaced features
// with affecting vulnerabilities.
func (tx *pgSession) FindAffectedNamespacedFeatures(features []database.NamespacedFeature) ([]database.NullableAffectedNamespacedFeature, error) {
	return vulnerability.FindAffectedNamespacedFeatures(tx.Tx, features)
}

// PersistNamespaces inserts a set of namespaces if not in the database.
func (tx *pgSession) PersistNamespaces(namespaces []database.Namespace) error {
	return namespace.PersistNamespaces(tx.Tx, namespaces)
}

// PersistLayer appends a layer's content in the database.
func (tx *pgSession) PersistLayer(hash string, features []database.LayerFeature, namespaces []database.LayerNamespace, detectedBy []database.Detector) error {
	return layer.PersistLayer(tx.Tx, hash, features, namespaces, detectedBy)
}

func (tx *pgSession) FindLayer(hash string) (database.Layer, bool, error) {
	return layer.FindLayer(tx.Tx, hash)
}

// InsertVulnerabilities inserts a set of UNIQUE vulnerabilities with
// affected features into database, assuming that all vulnerabilities
// provided are NOT in database and all vulnerabilities' namespaces are
// already in the database.
func (tx *pgSession) InsertVulnerabilities(vulns []database.VulnerabilityWithAffected) error {
	return vulnerability.InsertVulnerabilities(tx.Tx, vulns)
}

// FindVulnerability retrieves a set of Vulnerabilities with affected
// features.
func (tx *pgSession) FindVulnerabilities(ids []database.VulnerabilityID) ([]database.NullableVulnerability, error) {
	return vulnerability.FindVulnerabilities(tx.Tx, ids)
}

// DeleteVulnerability removes a set of Vulnerabilities assuming that the
// requested vulnerabilities are in the database.
func (tx *pgSession) DeleteVulnerabilities(ids []database.VulnerabilityID) error {
	return vulnerability.DeleteVulnerabilities(tx.Tx, ids)
}

// InsertVulnerabilityNotifications inserts a set of unique vulnerability
// notifications into datastore, assuming that they are not in the database.
func (tx *pgSession) InsertVulnerabilityNotifications(notifications []database.VulnerabilityNotification) error {
	return notification.InsertVulnerabilityNotifications(tx.Tx, notifications)
}

func (tx *pgSession) FindNewNotification(notifiedBefore time.Time) (hook database.NotificationHook, found bool, err error) {
	return notification.FindNewNotification(tx.Tx, notifiedBefore)
}

func (tx *pgSession) FindVulnerabilityNotification(name string, limit int, oldVulnerabilityPage pagination.Token, newVulnerabilityPage pagination.Token) (noti database.VulnerabilityNotificationWithVulnerable, found bool, err error) {
	return notification.FindVulnerabilityNotification(tx.Tx, name, limit, oldVulnerabilityPage, newVulnerabilityPage, tx.key)
}

// MarkNotificationAsRead marks a Notification as notified now, assuming
// the requested notification is in the database.
func (tx *pgSession) MarkNotificationAsRead(name string) error {
	return notification.MarkNotificationAsRead(tx.Tx, name)
}

// DeleteNotification removes a Notification in the database.
func (tx *pgSession) DeleteNotification(name string) error {
	return notification.DeleteNotification(tx.Tx, name)
}

// UpdateKeyValue stores or updates a simple key/value pair.
func (tx *pgSession) UpdateKeyValue(key, value string) error {
	return keyvalue.UpdateKeyValue(tx.Tx, key, value)
}

// FindKeyValue retrieves a value from the given key.
func (tx *pgSession) FindKeyValue(key string) (value string, found bool, err error) {
	return keyvalue.FindKeyValue(tx.Tx, key)
}

// AcquireLock acquires a brand new lock in the database with a given name
// for the given duration.
//
// A lock can only have one owner.
// This method should NOT block until a lock is acquired.
func (tx *pgSession) AcquireLock(name, owner string, duration time.Duration) (acquired bool, expiration time.Time, err error) {
	return lock.AcquireLock(tx.Tx, name, owner, duration)
}

// ExtendLock extends an existing lock such that the lock will expire at the
// current time plus the provided duration.
//
// This method should return immediately with an error if the lock does not
// exist.
func (tx *pgSession) ExtendLock(name, owner string, duration time.Duration) (extended bool, expiration time.Time, err error) {
	return lock.ExtendLock(tx.Tx, name, owner, duration)
}

// ReleaseLock releases an existing lock.
func (tx *pgSession) ReleaseLock(name, owner string) error {
	return lock.ReleaseLock(tx.Tx, name, owner)
}
