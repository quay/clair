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

// MockDatastore implements Datastore and enables overriding each available method.
// The default behavior of each method is to simply panic.
type MockDatastore struct {
	FctListNamespaces           func() ([]Namespace, error)
	FctInsertLayer              func(Layer) error
	FctFindLayer                func(name string, withFeatures, withVulnerabilities bool) (Layer, error)
	FctDeleteLayer              func(name string) error
	FctListVulnerabilities      func(namespaceName string, limit int, page int) ([]Vulnerability, int, error)
	FctInsertVulnerabilities    func(vulnerabilities []Vulnerability, createNotification bool) error
	FctFindVulnerability        func(namespaceName, name string) (Vulnerability, error)
	FctDeleteVulnerability      func(namespaceName, name string) error
	FctInsertVulnerabilityFixes func(vulnerabilityNamespace, vulnerabilityName string, fixes []FeatureVersion) error
	FctDeleteVulnerabilityFix   func(vulnerabilityNamespace, vulnerabilityName, featureName string) error
	FctGetAvailableNotification func(renotifyInterval time.Duration) (VulnerabilityNotification, error)
	FctGetNotification          func(name string, limit int, page VulnerabilityNotificationPageNumber) (VulnerabilityNotification, VulnerabilityNotificationPageNumber, error)
	FctSetNotificationNotified  func(name string) error
	FctDeleteNotification       func(name string) error
	FctInsertKeyValue           func(key, value string) error
	FctGetKeyValue              func(key string) (string, error)
	FctLock                     func(name string, owner string, duration time.Duration, renew bool) (bool, time.Time)
	FctUnlock                   func(name, owner string)
	FctFindLock                 func(name string) (string, time.Time, error)
	FctPing                     func() bool
	FctClose                    func()
}

func (mds *MockDatastore) ListNamespaces() ([]Namespace, error) {
	if mds.FctListNamespaces != nil {
		return mds.FctListNamespaces()
	}
	panic("required mock function not implemented")
}

func (mds *MockDatastore) InsertLayer(layer Layer) error {
	if mds.FctInsertLayer != nil {
		return mds.FctInsertLayer(layer)
	}
	panic("required mock function not implemented")
}

func (mds *MockDatastore) FindLayer(name string, withFeatures, withVulnerabilities bool) (Layer, error) {
	if mds.FctFindLayer != nil {
		return mds.FctFindLayer(name, withFeatures, withVulnerabilities)
	}
	panic("required mock function not implemented")
}

func (mds *MockDatastore) DeleteLayer(name string) error {
	if mds.FctDeleteLayer != nil {
		return mds.FctDeleteLayer(name)
	}
	panic("required mock function not implemented")
}

func (mds *MockDatastore) ListVulnerabilities(namespaceName string, limit int, page int) ([]Vulnerability, int, error) {
	if mds.FctListVulnerabilities != nil {
		return mds.FctListVulnerabilities(namespaceName, limit, page)
	}
	panic("required mock function not implemented")
}

func (mds *MockDatastore) InsertVulnerabilities(vulnerabilities []Vulnerability, createNotification bool) error {
	if mds.FctInsertVulnerabilities != nil {
		return mds.FctInsertVulnerabilities(vulnerabilities, createNotification)
	}
	panic("required mock function not implemented")
}

func (mds *MockDatastore) FindVulnerability(namespaceName, name string) (Vulnerability, error) {
	if mds.FctFindVulnerability != nil {
		return mds.FctFindVulnerability(namespaceName, name)
	}
	panic("required mock function not implemented")
}

func (mds *MockDatastore) DeleteVulnerability(namespaceName, name string) error {
	if mds.FctDeleteVulnerability != nil {
		return mds.FctDeleteVulnerability(namespaceName, name)
	}
	panic("required mock function not implemented")
}

func (mds *MockDatastore) InsertVulnerabilityFixes(vulnerabilityNamespace, vulnerabilityName string, fixes []FeatureVersion) error {
	if mds.FctInsertVulnerabilityFixes != nil {
		return mds.FctInsertVulnerabilityFixes(vulnerabilityNamespace, vulnerabilityName, fixes)
	}
	panic("required mock function not implemented")
}

func (mds *MockDatastore) DeleteVulnerabilityFix(vulnerabilityNamespace, vulnerabilityName, featureName string) error {
	if mds.FctDeleteVulnerabilityFix != nil {
		return mds.FctDeleteVulnerabilityFix(vulnerabilityNamespace, vulnerabilityName, featureName)
	}
	panic("required mock function not implemented")
}

func (mds *MockDatastore) GetAvailableNotification(renotifyInterval time.Duration) (VulnerabilityNotification, error) {
	if mds.FctGetAvailableNotification != nil {
		return mds.FctGetAvailableNotification(renotifyInterval)
	}
	panic("required mock function not implemented")
}

func (mds *MockDatastore) GetNotification(name string, limit int, page VulnerabilityNotificationPageNumber) (VulnerabilityNotification, VulnerabilityNotificationPageNumber, error) {
	if mds.FctGetNotification != nil {
		return mds.FctGetNotification(name, limit, page)
	}
	panic("required mock function not implemented")
}

func (mds *MockDatastore) SetNotificationNotified(name string) error {
	if mds.FctSetNotificationNotified != nil {
		return mds.FctSetNotificationNotified(name)
	}
	panic("required mock function not implemented")
}

func (mds *MockDatastore) DeleteNotification(name string) error {
	if mds.FctDeleteNotification != nil {
		return mds.FctDeleteNotification(name)
	}
	panic("required mock function not implemented")
}
func (mds *MockDatastore) InsertKeyValue(key, value string) error {
	if mds.FctInsertKeyValue != nil {
		return mds.FctInsertKeyValue(key, value)
	}
	panic("required mock function not implemented")
}

func (mds *MockDatastore) GetKeyValue(key string) (string, error) {
	if mds.FctGetKeyValue != nil {
		return mds.FctGetKeyValue(key)
	}
	panic("required mock function not implemented")
}

func (mds *MockDatastore) Lock(name string, owner string, duration time.Duration, renew bool) (bool, time.Time) {
	if mds.FctLock != nil {
		return mds.FctLock(name, owner, duration, renew)
	}
	panic("required mock function not implemented")
}

func (mds *MockDatastore) Unlock(name, owner string) {
	if mds.FctUnlock != nil {
		mds.FctUnlock(name, owner)
		return
	}
	panic("required mock function not implemented")
}

func (mds *MockDatastore) FindLock(name string) (string, time.Time, error) {
	if mds.FctFindLock != nil {
		return mds.FctFindLock(name)
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
