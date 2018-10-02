// Copyright 2018 clair authors
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
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/pkg/pagination"
)

// int keys must be the consistent with the database ID.
var (
	realFeatures = map[int]database.Feature{
		1: {"ourchat", "0.5", "dpkg"},
		2: {"openssl", "1.0", "dpkg"},
		3: {"openssl", "2.0", "dpkg"},
		4: {"fake", "2.0", "rpm"},
	}

	realNamespaces = map[int]database.Namespace{
		1: {"debian:7", "dpkg"},
		2: {"debian:8", "dpkg"},
		3: {"fake:1.0", "rpm"},
	}

	realNamespacedFeatures = map[int]database.NamespacedFeature{
		1: {realFeatures[1], realNamespaces[1]},
		2: {realFeatures[2], realNamespaces[1]},
		3: {realFeatures[2], realNamespaces[2]},
		4: {realFeatures[3], realNamespaces[1]},
	}

	realDetectors = map[int]database.Detector{
		1: database.NewNamespaceDetector("os-release", "1.0"),
		2: database.NewFeatureDetector("dpkg", "1.0"),
		3: database.NewFeatureDetector("rpm", "1.0"),
		4: database.NewNamespaceDetector("apt-sources", "1.0"),
	}

	realLayers = map[int]database.Layer{
		2: {
			Hash: "layer-1",
			By:   []database.Detector{realDetectors[1], realDetectors[2]},
			Features: []database.LayerFeature{
				{realFeatures[1], realDetectors[2]},
				{realFeatures[2], realDetectors[2]},
			},
			Namespaces: []database.LayerNamespace{
				{realNamespaces[1], realDetectors[1]},
			},
		},
		6: {
			Hash: "layer-4",
			By:   []database.Detector{realDetectors[1], realDetectors[2], realDetectors[3], realDetectors[4]},
			Features: []database.LayerFeature{
				{realFeatures[4], realDetectors[3]},
				{realFeatures[3], realDetectors[2]},
			},
			Namespaces: []database.LayerNamespace{
				{realNamespaces[1], realDetectors[1]},
				{realNamespaces[3], realDetectors[4]},
			},
		},
	}

	realAncestries = map[int]database.Ancestry{
		2: {
			Name: "ancestry-2",
			By:   []database.Detector{realDetectors[2], realDetectors[1]},
			Layers: []database.AncestryLayer{
				{
					"layer-0",
					[]database.AncestryFeature{},
				},
				{
					"layer-1",
					[]database.AncestryFeature{},
				},
				{
					"layer-2",
					[]database.AncestryFeature{
						{
							realNamespacedFeatures[1],
							realDetectors[2],
							realDetectors[1],
						},
					},
				},
				{
					"layer-3b",
					[]database.AncestryFeature{
						{
							realNamespacedFeatures[3],
							realDetectors[2],
							realDetectors[1],
						},
					},
				},
			},
		},
	}

	realVulnerability = map[int]database.Vulnerability{
		1: {
			Name:        "CVE-OPENSSL-1-DEB7",
			Namespace:   realNamespaces[1],
			Description: "A vulnerability affecting OpenSSL < 2.0 on Debian 7.0",
			Link:        "http://google.com/#q=CVE-OPENSSL-1-DEB7",
			Severity:    database.HighSeverity,
		},
		2: {
			Name:        "CVE-NOPE",
			Namespace:   realNamespaces[1],
			Description: "A vulnerability affecting nothing",
			Severity:    database.UnknownSeverity,
		},
	}

	realNotification = map[int]database.VulnerabilityNotification{
		1: {
			NotificationHook: database.NotificationHook{
				Name: "test",
			},
			Old: takeVulnerabilityPointerFromMap(realVulnerability, 2),
			New: takeVulnerabilityPointerFromMap(realVulnerability, 1),
		},
	}

	fakeFeatures = map[int]database.Feature{
		1: {
			Name:          "ourchat",
			Version:       "0.6",
			VersionFormat: "dpkg",
		},
	}

	fakeNamespaces = map[int]database.Namespace{
		1: {"green hat", "rpm"},
	}
	fakeNamespacedFeatures = map[int]database.NamespacedFeature{
		1: {
			Feature:   fakeFeatures[0],
			Namespace: realNamespaces[0],
		},
	}

	fakeDetector = map[int]database.Detector{
		1: {
			Name:    "fake",
			Version: "1.0",
			DType:   database.FeatureDetectorType,
		},
		2: {
			Name:    "fake2",
			Version: "2.0",
			DType:   database.NamespaceDetectorType,
		},
	}
)

func takeVulnerabilityPointerFromMap(m map[int]database.Vulnerability, id int) *database.Vulnerability {
	x := m[id]
	return &x
}

func takeAncestryPointerFromMap(m map[int]database.Ancestry, id int) *database.Ancestry {
	x := m[id]
	return &x
}

func takeLayerPointerFromMap(m map[int]database.Layer, id int) *database.Layer {
	x := m[id]
	return &x
}

func listNamespaces(t *testing.T, tx *pgSession) []database.Namespace {
	rows, err := tx.Query("SELECT name, version_format FROM namespace")
	if err != nil {
		t.FailNow()
	}
	defer rows.Close()

	namespaces := []database.Namespace{}
	for rows.Next() {
		var ns database.Namespace
		err := rows.Scan(&ns.Name, &ns.VersionFormat)
		if err != nil {
			t.FailNow()
		}
		namespaces = append(namespaces, ns)
	}

	return namespaces
}

func assertVulnerabilityNotificationWithVulnerableEqual(t *testing.T, key pagination.Key, expected, actual *database.VulnerabilityNotificationWithVulnerable) bool {
	if expected == actual {
		return true
	}

	if expected == nil || actual == nil {
		return assert.Equal(t, expected, actual)
	}

	return assert.Equal(t, expected.NotificationHook, actual.NotificationHook) &&
		AssertPagedVulnerableAncestriesEqual(t, key, expected.Old, actual.Old) &&
		AssertPagedVulnerableAncestriesEqual(t, key, expected.New, actual.New)
}

func AssertPagedVulnerableAncestriesEqual(t *testing.T, key pagination.Key, expected, actual *database.PagedVulnerableAncestries) bool {
	if expected == actual {
		return true
	}

	if expected == nil || actual == nil {
		return assert.Equal(t, expected, actual)
	}

	return database.AssertVulnerabilityEqual(t, &expected.Vulnerability, &actual.Vulnerability) &&
		assert.Equal(t, expected.Limit, actual.Limit) &&
		assert.Equal(t, mustUnmarshalToken(key, expected.Current), mustUnmarshalToken(key, actual.Current)) &&
		assert.Equal(t, mustUnmarshalToken(key, expected.Next), mustUnmarshalToken(key, actual.Next)) &&
		assert.Equal(t, expected.End, actual.End) &&
		database.AssertIntStringMapEqual(t, expected.Affected, actual.Affected)
}

func mustUnmarshalToken(key pagination.Key, token pagination.Token) Page {
	if token == pagination.FirstPageToken {
		return Page{}
	}

	p := Page{}
	if err := key.UnmarshalToken(token, &p); err != nil {
		panic(err)
	}

	return p
}

func mustMarshalToken(key pagination.Key, v interface{}) pagination.Token {
	token, err := key.MarshalToken(v)
	if err != nil {
		panic(err)
	}

	return token
}
