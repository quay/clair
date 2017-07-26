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

package database

import "time"

// MockSession implements Session and enables overriding each available method.
// The default behavior of each method is to simply panic.
type MockSession struct {
	FctCommit                           func() error
	FctRollback                         func() error
	FctUpsertAncestry                   func(Ancestry, []NamespacedFeature, Processors) error
	FctFindAncestry                     func(name string) (Ancestry, Processors, bool, error)
	FctFindAncestryFeatures             func(name string) (AncestryWithFeatures, bool, error)
	FctFindAffectedNamespacedFeatures   func(features []NamespacedFeature) ([]NullableAffectedNamespacedFeature, error)
	FctPersistNamespaces                func([]Namespace) error
	FctPersistFeatures                  func([]Feature) error
	FctPersistNamespacedFeatures        func([]NamespacedFeature) error
	FctCacheAffectedNamespacedFeatures  func([]NamespacedFeature) error
	FctPersistLayer                     func(Layer) error
	FctPersistLayerContent              func(hash string, namespaces []Namespace, features []Feature, processedBy Processors) error
	FctFindLayer                        func(name string) (Layer, Processors, bool, error)
	FctFindLayerWithContent             func(name string) (LayerWithContent, bool, error)
	FctInsertVulnerabilities            func([]VulnerabilityWithAffected) error
	FctFindVulnerabilities              func([]VulnerabilityID) ([]NullableVulnerability, error)
	FctDeleteVulnerabilities            func([]VulnerabilityID) error
	FctInsertVulnerabilityNotifications func([]VulnerabilityNotification) error
	FctFindNewNotification              func(lastNotified time.Time) (NotificationHook, bool, error)
	FctFindVulnerabilityNotification    func(name string, limit int, oldPage PageNumber, newPage PageNumber) (
		vuln VulnerabilityNotificationWithVulnerable, ok bool, err error)
	FctMarkNotificationNotified func(name string) error
	FctDeleteNotification       func(name string) error
	FctUpdateKeyValue           func(key, value string) error
	FctFindKeyValue             func(key string) (string, bool, error)
	FctLock                     func(name string, owner string, duration time.Duration, renew bool) (bool, time.Time, error)
	FctUnlock                   func(name, owner string) error
	FctFindLock                 func(name string) (string, time.Time, bool, error)
}

func (ms *MockSession) Commit() error {
	if ms.FctCommit != nil {
		return ms.FctCommit()
	}
	panic("required mock function not implemented")
}

func (ms *MockSession) Rollback() error {
	if ms.FctRollback != nil {
		return ms.FctRollback()
	}
	panic("required mock function not implemented")
}

func (ms *MockSession) UpsertAncestry(ancestry Ancestry, features []NamespacedFeature, processedBy Processors) error {
	if ms.FctUpsertAncestry != nil {
		return ms.FctUpsertAncestry(ancestry, features, processedBy)
	}
	panic("required mock function not implemented")
}

func (ms *MockSession) FindAncestry(name string) (Ancestry, Processors, bool, error) {
	if ms.FctFindAncestry != nil {
		return ms.FctFindAncestry(name)
	}
	panic("required mock function not implemented")
}

func (ms *MockSession) FindAncestryFeatures(name string) (AncestryWithFeatures, bool, error) {
	if ms.FctFindAncestryFeatures != nil {
		return ms.FctFindAncestryFeatures(name)
	}
	panic("required mock function not implemented")
}

func (ms *MockSession) FindAffectedNamespacedFeatures(features []NamespacedFeature) ([]NullableAffectedNamespacedFeature, error) {
	if ms.FctFindAffectedNamespacedFeatures != nil {
		return ms.FctFindAffectedNamespacedFeatures(features)
	}
	panic("required mock function not implemented")
}

func (ms *MockSession) PersistNamespaces(namespaces []Namespace) error {
	if ms.FctPersistNamespaces != nil {
		return ms.FctPersistNamespaces(namespaces)
	}
	panic("required mock function not implemented")
}

func (ms *MockSession) PersistFeatures(features []Feature) error {
	if ms.FctPersistFeatures != nil {
		return ms.FctPersistFeatures(features)
	}
	panic("required mock function not implemented")
}

func (ms *MockSession) PersistNamespacedFeatures(namespacedFeatures []NamespacedFeature) error {
	if ms.FctPersistNamespacedFeatures != nil {
		return ms.FctPersistNamespacedFeatures(namespacedFeatures)
	}
	panic("required mock function not implemented")
}

func (ms *MockSession) CacheAffectedNamespacedFeatures(namespacedFeatures []NamespacedFeature) error {
	if ms.FctCacheAffectedNamespacedFeatures != nil {
		return ms.FctCacheAffectedNamespacedFeatures(namespacedFeatures)
	}
	panic("required mock function not implemented")
}

func (ms *MockSession) PersistLayer(layer Layer) error {
	if ms.FctPersistLayer != nil {
		return ms.FctPersistLayer(layer)
	}
	panic("required mock function not implemented")
}

func (ms *MockSession) PersistLayerContent(hash string, namespaces []Namespace, features []Feature, processedBy Processors) error {
	if ms.FctPersistLayerContent != nil {
		return ms.FctPersistLayerContent(hash, namespaces, features, processedBy)
	}
	panic("required mock function not implemented")
}

func (ms *MockSession) FindLayer(name string) (Layer, Processors, bool, error) {
	if ms.FctFindLayer != nil {
		return ms.FctFindLayer(name)
	}
	panic("required mock function not implemented")
}

func (ms *MockSession) FindLayerWithContent(name string) (LayerWithContent, bool, error) {
	if ms.FctFindLayerWithContent != nil {
		return ms.FctFindLayerWithContent(name)
	}
	panic("required mock function not implemented")
}

func (ms *MockSession) InsertVulnerabilities(vulnerabilities []VulnerabilityWithAffected) error {
	if ms.FctInsertVulnerabilities != nil {
		return ms.FctInsertVulnerabilities(vulnerabilities)
	}
	panic("required mock function not implemented")
}

func (ms *MockSession) FindVulnerabilities(vulnerabilityIDs []VulnerabilityID) ([]NullableVulnerability, error) {
	if ms.FctFindVulnerabilities != nil {
		return ms.FctFindVulnerabilities(vulnerabilityIDs)
	}
	panic("required mock function not implemented")
}

func (ms *MockSession) DeleteVulnerabilities(VulnerabilityIDs []VulnerabilityID) error {
	if ms.FctDeleteVulnerabilities != nil {
		return ms.FctDeleteVulnerabilities(VulnerabilityIDs)
	}
	panic("required mock function not implemented")
}

func (ms *MockSession) InsertVulnerabilityNotifications(vulnerabilityNotifications []VulnerabilityNotification) error {
	if ms.FctInsertVulnerabilityNotifications != nil {
		return ms.FctInsertVulnerabilityNotifications(vulnerabilityNotifications)
	}
	panic("required mock function not implemented")
}

func (ms *MockSession) FindNewNotification(lastNotified time.Time) (NotificationHook, bool, error) {
	if ms.FctFindNewNotification != nil {
		return ms.FctFindNewNotification(lastNotified)
	}
	panic("required mock function not implemented")
}

func (ms *MockSession) FindVulnerabilityNotification(name string, limit int, oldPage PageNumber, newPage PageNumber) (
	VulnerabilityNotificationWithVulnerable, bool, error) {
	if ms.FctFindVulnerabilityNotification != nil {
		return ms.FctFindVulnerabilityNotification(name, limit, oldPage, newPage)
	}
	panic("required mock function not implemented")
}

func (ms *MockSession) MarkNotificationNotified(name string) error {
	if ms.FctMarkNotificationNotified != nil {
		return ms.FctMarkNotificationNotified(name)
	}
	panic("required mock function not implemented")
}

func (ms *MockSession) DeleteNotification(name string) error {
	if ms.FctDeleteNotification != nil {
		return ms.FctDeleteNotification(name)
	}
	panic("required mock function not implemented")
}

func (ms *MockSession) UpdateKeyValue(key, value string) error {
	if ms.FctUpdateKeyValue != nil {
		return ms.FctUpdateKeyValue(key, value)
	}
	panic("required mock function not implemented")
}

func (ms *MockSession) FindKeyValue(key string) (string, bool, error) {
	if ms.FctFindKeyValue != nil {
		return ms.FctFindKeyValue(key)
	}
	panic("required mock function not implemented")
}

func (ms *MockSession) Lock(name string, owner string, duration time.Duration, renew bool) (bool, time.Time, error) {
	if ms.FctLock != nil {
		return ms.FctLock(name, owner, duration, renew)
	}
	panic("required mock function not implemented")
}

func (ms *MockSession) Unlock(name, owner string) error {
	if ms.FctUnlock != nil {
		return ms.FctUnlock(name, owner)
	}
	panic("required mock function not implemented")
}

func (ms *MockSession) FindLock(name string) (string, time.Time, bool, error) {
	if ms.FctFindLock != nil {
		return ms.FctFindLock(name)
	}
	panic("required mock function not implemented")
}

// MockDatastore implements Datastore and enables overriding each available method.
// The default behavior of each method is to simply panic.
type MockDatastore struct {
	FctBegin func() (Session, error)
	FctPing  func() bool
	FctClose func()
}

func (mds *MockDatastore) Begin() (Session, error) {
	if mds.FctBegin != nil {
		return mds.FctBegin()
	}
	panic("required mock function not implemented")
}

func (mds *MockDatastore) Ping() bool {
	if mds.FctPing != nil {
		return mds.FctPing()
	}
	panic("required mock function not implemented")
}

func (mds *MockDatastore) Close() {
	if mds.FctClose != nil {
		mds.FctClose()
		return
	}
	panic("required mock function not implemented")
}
