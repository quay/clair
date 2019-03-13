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

// Enforce the interface at compile time.
var _ database.Session = &pgSession{}

type pgSession struct {
	*sql.Tx

	key pagination.Key
}

func (tx *pgSession) UpsertAncestry(a database.Ancestry) error {
	return ancestry.UpsertAncestry(tx.Tx, a)
}

func (tx *pgSession) FindAncestry(name string) (database.Ancestry, bool, error) {
	return ancestry.FindAncestry(tx.Tx, name)
}

func (tx *pgSession) PersistDetectors(detectors []database.Detector) error {
	return detector.PersistDetectors(tx.Tx, detectors)
}

func (tx *pgSession) PersistFeatures(features []database.Feature) error {
	return feature.PersistFeatures(tx.Tx, features)
}

func (tx *pgSession) PersistNamespacedFeatures(features []database.NamespacedFeature) error {
	return feature.PersistNamespacedFeatures(tx.Tx, features)
}

func (tx *pgSession) CacheAffectedNamespacedFeatures(features []database.NamespacedFeature) error {
	return vulnerability.CacheAffectedNamespacedFeatures(tx.Tx, features)
}

func (tx *pgSession) FindAffectedNamespacedFeatures(features []database.NamespacedFeature) ([]database.NullableAffectedNamespacedFeature, error) {
	return vulnerability.FindAffectedNamespacedFeatures(tx.Tx, features)
}

func (tx *pgSession) PersistNamespaces(namespaces []database.Namespace) error {
	return namespace.PersistNamespaces(tx.Tx, namespaces)
}

func (tx *pgSession) PersistLayer(hash string, features []database.LayerFeature, namespaces []database.LayerNamespace, detectedBy []database.Detector) error {
	return layer.PersistLayer(tx.Tx, hash, features, namespaces, detectedBy)
}

func (tx *pgSession) FindLayer(hash string) (database.Layer, bool, error) {
	return layer.FindLayer(tx.Tx, hash)
}

func (tx *pgSession) InsertVulnerabilities(vulns []database.VulnerabilityWithAffected) error {
	return vulnerability.InsertVulnerabilities(tx.Tx, vulns)
}

func (tx *pgSession) FindVulnerabilities(ids []database.VulnerabilityID) ([]database.NullableVulnerability, error) {
	return vulnerability.FindVulnerabilities(tx.Tx, ids)
}

func (tx *pgSession) DeleteVulnerabilities(ids []database.VulnerabilityID) error {
	return vulnerability.DeleteVulnerabilities(tx.Tx, ids)
}

func (tx *pgSession) InsertVulnerabilityNotifications(notifications []database.VulnerabilityNotification) error {
	return notification.InsertVulnerabilityNotifications(tx.Tx, notifications)
}

func (tx *pgSession) FindNewNotification(notifiedBefore time.Time) (hook database.NotificationHook, found bool, err error) {
	return notification.FindNewNotification(tx.Tx, notifiedBefore)
}

func (tx *pgSession) FindVulnerabilityNotification(name string, limit int, oldVulnerabilityPage pagination.Token, newVulnerabilityPage pagination.Token) (noti database.VulnerabilityNotificationWithVulnerable, found bool, err error) {
	return notification.FindVulnerabilityNotification(tx.Tx, name, limit, oldVulnerabilityPage, newVulnerabilityPage, tx.key)
}

func (tx *pgSession) MarkNotificationAsRead(name string) error {
	return notification.MarkNotificationAsRead(tx.Tx, name)
}

func (tx *pgSession) DeleteNotification(name string) error {
	return notification.DeleteNotification(tx.Tx, name)
}

func (tx *pgSession) UpdateKeyValue(key, value string) error {
	return keyvalue.UpdateKeyValue(tx.Tx, key, value)
}

func (tx *pgSession) FindKeyValue(key string) (value string, found bool, err error) {
	return keyvalue.FindKeyValue(tx.Tx, key)
}

func (tx *pgSession) AcquireLock(name, owner string, duration time.Duration) (acquired bool, expiration time.Time, err error) {
	return lock.AcquireLock(tx.Tx, name, owner, duration)
}

func (tx *pgSession) ExtendLock(name, owner string, duration time.Duration) (extended bool, expiration time.Time, err error) {
	return lock.ExtendLock(tx.Tx, name, owner, duration)
}

func (tx *pgSession) ReleaseLock(name, owner string) error {
	return lock.ReleaseLock(tx.Tx, name, owner)
}
