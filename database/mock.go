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

import (
	"github.com/coreos/clair/services"
	"time"
)

// MockBase implements services.Base
type MockBase struct {
	FctPing  func() bool
	FctClose func()
}

func (mds *MockBase) Ping() bool {
	if mds.FctPing != nil {
		return mds.FctPing()
	}
	panic("required mock function not implemented")
}

func (mds *MockBase) Close() {
	if mds.FctClose != nil {
		mds.FctClose()
		return
	}
	panic("required mock function not implemented")
}

// MockLock implements locks.Service and enables overriding each available method.
// The default behavior of each method is to simply panic.
type MockLock struct {
	MockBase
	FctLock     func(name string, owner string, duration time.Duration, renew bool) (bool, time.Time)
	FctUnlock   func(name, owner string)
	FctFindLock func(name string) (string, time.Time, error)
}

func (mds *MockLock) Lock(name string, owner string, duration time.Duration, renew bool) (bool, time.Time) {
	if mds.FctLock != nil {
		return mds.FctLock(name, owner, duration, renew)
	}
	panic("required mock function not implemented")
}

func (mds *MockLock) Unlock(name, owner string) {
	if mds.FctUnlock != nil {
		mds.FctUnlock(name, owner)
		return
	}
	panic("required mock function not implemented")
}

func (mds *MockLock) FindLock(name string) (string, time.Time, error) {
	if mds.FctFindLock != nil {
		return mds.FctFindLock(name)
	}
	panic("required mock function not implemented")
}

// MockKeyValue implements keyvalue.Service and enables overriding each available method.
// The default behavior of each method is to simply panic.
type MockKeyValue struct {
	MockBase
	FctInsertKeyValue func(key, value string) error
	FctGetKeyValue    func(key string) (string, error)
}

func (mds *MockKeyValue) InsertKeyValue(key, value string) error {
	if mds.FctInsertKeyValue != nil {
		return mds.FctInsertKeyValue(key, value)
	}
	panic("required mock function not implemented")
}

func (mds *MockKeyValue) GetKeyValue(key string) (string, error) {
	if mds.FctGetKeyValue != nil {
		return mds.FctGetKeyValue(key)
	}
	panic("required mock function not implemented")
}

// MockNotification implements notifications.Service and enables overriding each available method.
// The default behavior of each method is to simply panic.
type MockNotification struct {
	MockBase
	FctGetAvailableNotification func(renotifyInterval time.Duration) (services.VulnerabilityNotification, error)
	FctGetNotification          func(name string, limit int, page services.VulnerabilityNotificationPageNumber) (services.VulnerabilityNotification, services.VulnerabilityNotificationPageNumber, error)
	FctSetNotificationNotified  func(name string) error
	FctDeleteNotification       func(name string) error
}

func (mds *MockNotification) GetAvailableNotification(renotifyInterval time.Duration) (services.VulnerabilityNotification, error) {
	if mds.FctGetAvailableNotification != nil {
		return mds.FctGetAvailableNotification(renotifyInterval)
	}
	panic("required mock function not implemented")
}

func (mds *MockNotification) GetNotification(name string, limit int, page services.VulnerabilityNotificationPageNumber) (services.VulnerabilityNotification, services.VulnerabilityNotificationPageNumber, error) {
	if mds.FctGetNotification != nil {
		return mds.FctGetNotification(name, limit, page)
	}
	panic("required mock function not implemented")
}

func (mds *MockNotification) SetNotificationNotified(name string) error {
	if mds.FctSetNotificationNotified != nil {
		return mds.FctSetNotificationNotified(name)
	}
	panic("required mock function not implemented")
}

func (mds *MockNotification) DeleteNotification(name string) error {
	if mds.FctDeleteNotification != nil {
		return mds.FctDeleteNotification(name)
	}
	panic("required mock function not implemented")
}

// MockVulnerabilities implements vulnerabilities.Service and enables overriding each available method.
// The default behavior of each method is to simply panic.
type MockVulnerabilities struct {
	MockBase
	FctListNamespaces           func() ([]services.Namespace, error)
	FctInsertLayer              func(services.Layer) error
	FctFindLayer                func(name string, withFeatures, withVulnerabilities bool) (services.Layer, error)
	FctDeleteLayer              func(name string) error
	FctListVulnerabilities      func(namespaceName string, limit int, page int) ([]services.Vulnerability, int, error)
	FctInsertVulnerabilities    func(vulnerabilities []services.Vulnerability, createNotification bool) error
	FctFindVulnerability        func(namespaceName, name string) (services.Vulnerability, error)
	FctDeleteVulnerability      func(namespaceName, name string) error
	FctInsertVulnerabilityFixes func(vulnerabilityNamespace, vulnerabilityName string, fixes []services.FeatureVersion) error
	FctDeleteVulnerabilityFix   func(vulnerabilityNamespace, vulnerabilityName, featureName string) error
}

func (mds *MockVulnerabilities) ListNamespaces() ([]services.Namespace, error) {
	if mds.FctListNamespaces != nil {
		return mds.FctListNamespaces()
	}
	panic("required mock function not implemented")
}

func (mds *MockVulnerabilities) InsertLayer(layer services.Layer) error {
	if mds.FctInsertLayer != nil {
		return mds.FctInsertLayer(layer)
	}
	panic("required mock function not implemented")
}

func (mds *MockVulnerabilities) FindLayer(name string, withFeatures, withVulnerabilities bool) (services.Layer, error) {
	if mds.FctFindLayer != nil {
		return mds.FctFindLayer(name, withFeatures, withVulnerabilities)
	}
	panic("required mock function not implemented")
}

func (mds *MockVulnerabilities) DeleteLayer(name string) error {
	if mds.FctDeleteLayer != nil {
		return mds.FctDeleteLayer(name)
	}
	panic("required mock function not implemented")
}

func (mds *MockVulnerabilities) ListVulnerabilities(namespaceName string, limit int, page int) ([]services.Vulnerability, int, error) {
	if mds.FctListVulnerabilities != nil {
		return mds.FctListVulnerabilities(namespaceName, limit, page)
	}
	panic("required mock function not implemented")
}

func (mds *MockVulnerabilities) InsertVulnerabilities(vulnerabilities []services.Vulnerability, createNotification bool) error {
	if mds.FctInsertVulnerabilities != nil {
		return mds.FctInsertVulnerabilities(vulnerabilities, createNotification)
	}
	panic("required mock function not implemented")
}

func (mds *MockVulnerabilities) FindVulnerability(namespaceName, name string) (services.Vulnerability, error) {
	if mds.FctFindVulnerability != nil {
		return mds.FctFindVulnerability(namespaceName, name)
	}
	panic("required mock function not implemented")
}

func (mds *MockVulnerabilities) DeleteVulnerability(namespaceName, name string) error {
	if mds.FctDeleteVulnerability != nil {
		return mds.FctDeleteVulnerability(namespaceName, name)
	}
	panic("required mock function not implemented")
}

func (mds *MockVulnerabilities) InsertVulnerabilityFixes(vulnerabilityNamespace, vulnerabilityName string, fixes []services.FeatureVersion) error {
	if mds.FctInsertVulnerabilityFixes != nil {
		return mds.FctInsertVulnerabilityFixes(vulnerabilityNamespace, vulnerabilityName, fixes)
	}
	panic("required mock function not implemented")
}

func (mds *MockVulnerabilities) DeleteVulnerabilityFix(vulnerabilityNamespace, vulnerabilityName, featureName string) error {
	if mds.FctDeleteVulnerabilityFix != nil {
		return mds.FctDeleteVulnerabilityFix(vulnerabilityNamespace, vulnerabilityName, featureName)
	}
	panic("required mock function not implemented")
}
