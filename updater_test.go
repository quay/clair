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

package clair

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/coreos/clair/database"
	"github.com/stretchr/testify/assert"
)

type mockUpdaterDatastore struct {
	database.MockDatastore

	namespaces       map[string]database.Namespace
	vulnerabilities  map[database.VulnerabilityID]database.VulnerabilityWithAffected
	vulnNotification map[string]database.VulnerabilityNotification
	keyValues        map[string]string
}

type mockUpdaterSession struct {
	database.MockSession

	store      *mockUpdaterDatastore
	copy       mockUpdaterDatastore
	terminated bool
}

func copyUpdaterDatastore(md *mockUpdaterDatastore) mockUpdaterDatastore {
	namespaces := map[string]database.Namespace{}
	for k, n := range md.namespaces {
		namespaces[k] = n
	}

	vulnerabilities := map[database.VulnerabilityID]database.VulnerabilityWithAffected{}
	for key, v := range md.vulnerabilities {
		newV := v
		affected := []database.AffectedFeature{}
		for _, f := range v.Affected {
			affected = append(affected, f)
		}
		newV.Affected = affected
		vulnerabilities[key] = newV
	}

	vulnNoti := map[string]database.VulnerabilityNotification{}
	for key, v := range md.vulnNotification {
		vulnNoti[key] = v
	}

	kv := map[string]string{}
	for key, value := range md.keyValues {
		kv[key] = value
	}

	return mockUpdaterDatastore{
		namespaces:       namespaces,
		vulnerabilities:  vulnerabilities,
		vulnNotification: vulnNoti,
		keyValues:        kv,
	}
}

func newmockUpdaterDatastore() *mockUpdaterDatastore {
	errSessionDone := errors.New("Session Done")
	md := &mockUpdaterDatastore{
		namespaces:       make(map[string]database.Namespace),
		vulnerabilities:  make(map[database.VulnerabilityID]database.VulnerabilityWithAffected),
		vulnNotification: make(map[string]database.VulnerabilityNotification),
		keyValues:        make(map[string]string),
	}

	md.FctBegin = func() (database.Session, error) {
		session := &mockUpdaterSession{
			store:      md,
			copy:       copyUpdaterDatastore(md),
			terminated: false,
		}

		session.FctCommit = func() error {
			if session.terminated {
				return errSessionDone
			}
			session.store.namespaces = session.copy.namespaces
			session.store.vulnerabilities = session.copy.vulnerabilities
			session.store.vulnNotification = session.copy.vulnNotification
			session.store.keyValues = session.copy.keyValues
			session.terminated = true
			return nil
		}

		session.FctRollback = func() error {
			if session.terminated {
				return errSessionDone
			}
			session.terminated = true
			session.copy = mockUpdaterDatastore{}
			return nil
		}

		session.FctPersistNamespaces = func(ns []database.Namespace) error {
			if session.terminated {
				return errSessionDone
			}
			for _, n := range ns {
				_, ok := session.copy.namespaces[n.Name]
				if !ok {
					session.copy.namespaces[n.Name] = n
				}
			}
			return nil
		}

		session.FctFindVulnerabilities = func(ids []database.VulnerabilityID) ([]database.NullableVulnerability, error) {
			r := []database.NullableVulnerability{}
			for _, id := range ids {
				vuln, ok := session.copy.vulnerabilities[id]
				r = append(r, database.NullableVulnerability{
					VulnerabilityWithAffected: vuln,
					Valid:                     ok,
				})
			}
			return r, nil
		}

		session.FctDeleteVulnerabilities = func(ids []database.VulnerabilityID) error {
			for _, id := range ids {
				delete(session.copy.vulnerabilities, id)
			}
			return nil
		}

		session.FctInsertVulnerabilities = func(vulnerabilities []database.VulnerabilityWithAffected) error {
			for _, vuln := range vulnerabilities {
				id := database.VulnerabilityID{
					Name:      vuln.Name,
					Namespace: vuln.Namespace.Name,
				}
				if _, ok := session.copy.vulnerabilities[id]; ok {
					return errors.New("Vulnerability already exists")
				}
				session.copy.vulnerabilities[id] = vuln
			}
			return nil
		}

		session.FctUpdateKeyValue = func(key, value string) error {
			session.copy.keyValues[key] = value
			return nil
		}

		session.FctFindKeyValue = func(key string) (string, bool, error) {
			s, b := session.copy.keyValues[key]
			return s, b, nil
		}

		session.FctInsertVulnerabilityNotifications = func(notifications []database.VulnerabilityNotification) error {
			for _, noti := range notifications {
				session.copy.vulnNotification[noti.Name] = noti
			}
			return nil
		}

		return session, nil
	}
	return md
}

func TestDoVulnerabilitiesNamespacing(t *testing.T) {
	fv1 := database.AffectedFeature{
		FeatureType:     database.SourcePackage,
		Namespace:       database.Namespace{Name: "Namespace1"},
		FeatureName:     "Feature1",
		FixedInVersion:  "0.1",
		AffectedVersion: "0.1",
	}

	fv2 := database.AffectedFeature{
		FeatureType:     database.SourcePackage,
		Namespace:       database.Namespace{Name: "Namespace2"},
		FeatureName:     "Feature1",
		FixedInVersion:  "0.2",
		AffectedVersion: "0.2",
	}

	fv3 := database.AffectedFeature{
		FeatureType:     database.SourcePackage,
		Namespace:       database.Namespace{Name: "Namespace2"},
		FeatureName:     "Feature2",
		FixedInVersion:  "0.3",
		AffectedVersion: "0.3",
	}

	vulnerability := database.VulnerabilityWithAffected{
		Vulnerability: database.Vulnerability{
			Name: "DoVulnerabilityNamespacing",
		},
		Affected: []database.AffectedFeature{fv1, fv2, fv3},
	}

	vulnerabilities := doVulnerabilitiesNamespacing([]database.VulnerabilityWithAffected{vulnerability})
	for _, vulnerability := range vulnerabilities {
		switch vulnerability.Namespace.Name {
		case fv1.Namespace.Name:
			assert.Len(t, vulnerability.Affected, 1)
			assert.Contains(t, vulnerability.Affected, fv1)
		case fv2.Namespace.Name:
			assert.Len(t, vulnerability.Affected, 2)
			assert.Contains(t, vulnerability.Affected, fv2)
			assert.Contains(t, vulnerability.Affected, fv3)
		default:
			t.Errorf("Should not have a Vulnerability with '%s' as its Namespace.", vulnerability.Namespace.Name)
			fmt.Printf("%#v\n", vulnerability)
		}
	}
}

func TestCreatVulnerabilityNotification(t *testing.T) {
	vf1 := "VersionFormat1"
	ns1 := database.Namespace{
		Name:          "namespace 1",
		VersionFormat: vf1,
	}
	af1 := database.AffectedFeature{
		FeatureType: database.SourcePackage,
		Namespace:   ns1,
		FeatureName: "feature 1",
	}

	v1 := database.VulnerabilityWithAffected{
		Vulnerability: database.Vulnerability{
			Name:      "vulnerability 1",
			Namespace: ns1,
			Severity:  database.UnknownSeverity,
		},
	}

	// severity change
	v2 := database.VulnerabilityWithAffected{
		Vulnerability: database.Vulnerability{
			Name:      "vulnerability 1",
			Namespace: ns1,
			Severity:  database.LowSeverity,
		},
	}

	// affected versions change
	v3 := database.VulnerabilityWithAffected{
		Vulnerability: database.Vulnerability{
			Name:      "vulnerability 1",
			Namespace: ns1,
			Severity:  database.UnknownSeverity,
		},
		Affected: []database.AffectedFeature{af1},
	}

	datastore := newmockUpdaterDatastore()
	change, err := updateVulnerabilities(context.TODO(), datastore, []database.VulnerabilityWithAffected{})
	assert.Nil(t, err)
	assert.Len(t, change, 0)

	change, err = updateVulnerabilities(context.TODO(), datastore, []database.VulnerabilityWithAffected{v1})
	assert.Nil(t, err)
	assert.Len(t, change, 1)
	assert.Nil(t, change[0].old)
	assertVulnerability(t, *change[0].new, v1)

	change, err = updateVulnerabilities(context.TODO(), datastore, []database.VulnerabilityWithAffected{v1})
	assert.Nil(t, err)
	assert.Len(t, change, 0)

	change, err = updateVulnerabilities(context.TODO(), datastore, []database.VulnerabilityWithAffected{v2})
	assert.Nil(t, err)
	assert.Len(t, change, 1)
	assertVulnerability(t, *change[0].new, v2)
	assertVulnerability(t, *change[0].old, v1)

	change, err = updateVulnerabilities(context.TODO(), datastore, []database.VulnerabilityWithAffected{v3})
	assert.Nil(t, err)
	assert.Len(t, change, 1)
	assertVulnerability(t, *change[0].new, v3)
	assertVulnerability(t, *change[0].old, v2)

	err = createVulnerabilityNotifications(datastore, change)
	assert.Nil(t, err)
	assert.Len(t, datastore.vulnNotification, 1)
	for _, noti := range datastore.vulnNotification {
		assert.Equal(t, *noti.New, v3.Vulnerability)
		assert.Equal(t, *noti.Old, v2.Vulnerability)
	}
}

func assertVulnerability(t *testing.T, expected database.VulnerabilityWithAffected, actual database.VulnerabilityWithAffected) bool {
	expectedAF := expected.Affected
	actualAF := actual.Affected
	expected.Affected, actual.Affected = nil, nil

	assert.Equal(t, expected, actual)
	assert.Len(t, actualAF, len(expectedAF))

	mapAF := map[database.AffectedFeature]bool{}
	for _, af := range expectedAF {
		mapAF[af] = false
	}

	for _, af := range actualAF {
		if visited, ok := mapAF[af]; !ok || visited {
			return false
		}
	}
	return true
}
