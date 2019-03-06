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

package testutil

import "github.com/coreos/clair/database"

// int keys must be the consistent with the database ID.
var (
	RealFeatures = map[int]database.Feature{
		1: {"ourchat", "0.5", "dpkg", "source"},
		2: {"openssl", "1.0", "dpkg", "source"},
		3: {"openssl", "2.0", "dpkg", "source"},
		4: {"fake", "2.0", "rpm", "source"},
		5: {"mount", "2.31.1-0.4ubuntu3.1", "dpkg", "binary"},
	}

	RealNamespaces = map[int]database.Namespace{
		1: {"debian:7", "dpkg"},
		2: {"debian:8", "dpkg"},
		3: {"fake:1.0", "rpm"},
		4: {"cpe:/o:redhat:enterprise_linux:7::server", "rpm"},
	}

	RealNamespacedFeatures = map[int]database.NamespacedFeature{
		1: {RealFeatures[1], RealNamespaces[1]},
		2: {RealFeatures[2], RealNamespaces[1]},
		3: {RealFeatures[2], RealNamespaces[2]},
		4: {RealFeatures[3], RealNamespaces[1]},
	}

	RealDetectors = map[int]database.Detector{
		1: database.NewNamespaceDetector("os-release", "1.0"),
		2: database.NewFeatureDetector("dpkg", "1.0"),
		3: database.NewFeatureDetector("rpm", "1.0"),
		4: database.NewNamespaceDetector("apt-sources", "1.0"),
	}

	RealLayers = map[int]database.Layer{
		2: {
			Hash: "layer-1",
			By:   []database.Detector{RealDetectors[1], RealDetectors[2]},
			Features: []database.LayerFeature{
				{RealFeatures[1], RealDetectors[2], database.Namespace{}},
				{RealFeatures[2], RealDetectors[2], database.Namespace{}},
			},
			Namespaces: []database.LayerNamespace{
				{RealNamespaces[1], RealDetectors[1]},
			},
		},
		6: {
			Hash: "layer-4",
			By:   []database.Detector{RealDetectors[1], RealDetectors[2], RealDetectors[3], RealDetectors[4]},
			Features: []database.LayerFeature{
				{RealFeatures[4], RealDetectors[3], database.Namespace{}},
				{RealFeatures[3], RealDetectors[2], database.Namespace{}},
			},
			Namespaces: []database.LayerNamespace{
				{RealNamespaces[1], RealDetectors[1]},
				{RealNamespaces[3], RealDetectors[4]},
			},
		},
	}

	RealAncestries = map[int]database.Ancestry{
		2: {
			Name: "ancestry-2",
			By:   []database.Detector{RealDetectors[2], RealDetectors[1]},
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
							RealNamespacedFeatures[1],
							RealDetectors[2],
							RealDetectors[1],
						},
					},
				},
				{
					"layer-3b",
					[]database.AncestryFeature{
						{
							RealNamespacedFeatures[3],
							RealDetectors[2],
							RealDetectors[1],
						},
					},
				},
			},
		},
	}

	RealVulnerability = map[int]database.Vulnerability{
		1: {
			Name:        "CVE-OPENSSL-1-DEB7",
			Namespace:   RealNamespaces[1],
			Description: "A vulnerability affecting OpenSSL < 2.0 on Debian 7.0",
			Link:        "http://google.com/#q=CVE-OPENSSL-1-DEB7",
			Severity:    database.HighSeverity,
		},
		2: {
			Name:        "CVE-NOPE",
			Namespace:   RealNamespaces[1],
			Description: "A vulnerability affecting nothing",
			Severity:    database.UnknownSeverity,
		},
	}

	RealNotification = map[int]database.VulnerabilityNotification{
		1: {
			NotificationHook: database.NotificationHook{
				Name: "test",
			},
			Old: takeVulnerabilityPointerFromMap(RealVulnerability, 2),
			New: takeVulnerabilityPointerFromMap(RealVulnerability, 1),
		},
	}

	FakeFeatures = map[int]database.Feature{
		1: {
			Name:          "ourchat",
			Version:       "0.6",
			VersionFormat: "dpkg",
			Type:          "source",
		},
	}

	FakeNamespaces = map[int]database.Namespace{
		1: {"green hat", "rpm"},
	}

	FakeNamespacedFeatures = map[int]database.NamespacedFeature{
		1: {
			Feature:   FakeFeatures[0],
			Namespace: RealNamespaces[0],
		},
	}

	FakeDetector = map[int]database.Detector{
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
