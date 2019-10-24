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

package redhatcpe

import (
	"testing"

	"github.com/quay/clair/v3/database"
	"github.com/quay/clair/v3/ext/featurefmt/redhatrpm"
	"github.com/quay/clair/v3/ext/versionfmt/rpm"
	"github.com/stretchr/testify/require"
)

func TestShareNamespaces(t *testing.T) {
	for _, test := range [...]struct {
		layers []*database.LayerScanResult

		layerNamespaces         map[string][]string
		expectedlayerNamespaces map[string][]string
	}{
		// Sharing namespace with parent layer
		{
			[]*database.LayerScanResult{
				&database.LayerScanResult{NewScanResultLayer: &database.Layer{Hash: "sha:111"}},
				&database.LayerScanResult{NewScanResultLayer: &database.Layer{Hash: "sha:222"}},
				&database.LayerScanResult{NewScanResultLayer: &database.Layer{Hash: "sha:333"}},
			},
			map[string][]string{
				"sha:222": []string{"cpe1", "cpe2"},
				"sha:333": []string{"cpe3", "cpe4"},
			},
			map[string][]string{
				"sha:111": []string{"cpe1", "cpe2"},
				"sha:222": []string{"cpe1", "cpe2"},
				"sha:333": []string{"cpe3", "cpe4"},
			},
		},
		// Sharing namespace with parent and child layer
		{
			[]*database.LayerScanResult{
				&database.LayerScanResult{NewScanResultLayer: &database.Layer{Hash: "sha:111"}},
				&database.LayerScanResult{NewScanResultLayer: &database.Layer{Hash: "sha:222"}},
				&database.LayerScanResult{NewScanResultLayer: &database.Layer{Hash: "sha:333"}},
				&database.LayerScanResult{NewScanResultLayer: &database.Layer{Hash: "sha:444"}},
			},
			map[string][]string{
				"sha:222": []string{"cpe1", "cpe2"},
				"sha:333": []string{"cpe3", "cpe4"},
			},
			map[string][]string{
				"sha:111": []string{"cpe1", "cpe2"},
				"sha:222": []string{"cpe1", "cpe2"},
				"sha:333": []string{"cpe3", "cpe4"},
				"sha:444": []string{"cpe3", "cpe4"},
			},
		},
		// Test with namespace gap
		{
			[]*database.LayerScanResult{
				&database.LayerScanResult{NewScanResultLayer: &database.Layer{Hash: "sha:111"}},
				&database.LayerScanResult{NewScanResultLayer: &database.Layer{Hash: "sha:222"}},
				&database.LayerScanResult{NewScanResultLayer: &database.Layer{Hash: "sha:333"}},
				&database.LayerScanResult{NewScanResultLayer: &database.Layer{Hash: "sha:444"}},
				&database.LayerScanResult{NewScanResultLayer: &database.Layer{Hash: "sha:555"}},
			},
			map[string][]string{
				"sha:222": []string{"cpe1", "cpe2"},
				"sha:444": []string{"cpe3", "cpe4"},
			},
			map[string][]string{
				"sha:111": []string{"cpe1", "cpe2"},
				"sha:222": []string{"cpe1", "cpe2"},
				"sha:333": []string{"cpe1", "cpe2"},
				"sha:444": []string{"cpe3", "cpe4"},
				"sha:555": []string{"cpe3", "cpe4"},
			},
		},
	} {
		outputLayerNamespaces := shareNamespaces(test.layers, test.layerNamespaces)

		require.Equal(t, test.expectedlayerNamespaces, outputLayerNamespaces)
	}
}

func TestIsRedHatImage(t *testing.T) {
	for _, test := range [...]struct {
		layers []*database.LayerScanResult

		expectedResult bool
	}{
		// Sharing namespace with parent layer
		{
			[]*database.LayerScanResult{
				&database.LayerScanResult{NewScanResultLayer: &database.Layer{Hash: "sha:111"}},
				&database.LayerScanResult{NewScanResultLayer: &database.Layer{Hash: "sha:222", Features: []database.LayerFeature{
					database.LayerFeature{
						Feature: database.Feature{Name: "fake-pkg", Version: "1", VersionFormat: "rpm", Type: database.BinaryPackage},
						By:      database.Detector{Name: "Non-RedHat"},
					},
				}}},
			},
			false,
		},
		{
			[]*database.LayerScanResult{
				&database.LayerScanResult{NewScanResultLayer: &database.Layer{Hash: "sha:111"}},
				&database.LayerScanResult{NewScanResultLayer: &database.Layer{Hash: "sha:222", Features: []database.LayerFeature{
					database.LayerFeature{
						Feature:            redhatrpm.NamespaceHolderPackage,
						By:                 database.Detector{Name: redhatrpm.Name},
						PotentialNamespace: database.Namespace{Name: "cpe:/o:redhat:enterprise_linux:7::computenode"},
					},
				}}},
			},
			true,
		},
	} {
		result := isRedHatImage(test.layers)

		require.Equal(t, test.expectedResult, result)
	}
}

func TestExtractCPEs(t *testing.T) {
	for _, test := range [...]struct {
		layers []*database.LayerScanResult

		expectedResult map[string][]string
	}{
		// Sharing namespace with parent layer
		{
			[]*database.LayerScanResult{
				&database.LayerScanResult{NewScanResultLayer: &database.Layer{Hash: "sha:111"}},
				&database.LayerScanResult{NewScanResultLayer: &database.Layer{Hash: "sha:222", Features: []database.LayerFeature{
					database.LayerFeature{
						Feature:            redhatrpm.NamespaceHolderPackage,
						By:                 database.Detector{Name: redhatrpm.Name},
						PotentialNamespace: database.Namespace{Name: "cpe:/o:redhat:enterprise_linux:7::computenode"},
					},
				}}},
				&database.LayerScanResult{NewScanResultLayer: &database.Layer{Hash: "sha:333", Features: []database.LayerFeature{
					database.LayerFeature{
						Feature:            redhatrpm.NamespaceHolderPackage,
						By:                 database.Detector{Name: redhatrpm.Name},
						PotentialNamespace: database.Namespace{Name: "cpe:/o:redhat:enterprise_linux:7::computenode"},
					},
					database.LayerFeature{
						Feature:            redhatrpm.NamespaceHolderPackage,
						By:                 database.Detector{Name: redhatrpm.Name},
						PotentialNamespace: database.Namespace{Name: "cpe:/o:redhat:enterprise_linux:7::computenode2"},
					},
				}}},
			},
			map[string][]string{
				"sha:222": []string{"cpe:/o:redhat:enterprise_linux:7::computenode"},
				"sha:333": []string{
					"cpe:/o:redhat:enterprise_linux:7::computenode",
					"cpe:/o:redhat:enterprise_linux:7::computenode2",
				},
			},
		},
	} {
		result := extractCPEs(test.layers)

		require.Equal(t, test.expectedResult, result)
	}
}

func TestPostProcessImage(t *testing.T) {
	for _, test := range [...]struct {
		layers []*database.LayerScanResult

		expectedResult []*database.LayerScanResult
	}{
		// Sharing namespace with parent layer
		{
			[]*database.LayerScanResult{
				// first layer with RH package but missing namespace
				&database.LayerScanResult{NewScanResultLayer: &database.Layer{Hash: "sha:111", Features: []database.LayerFeature{
					database.LayerFeature{
						Feature: database.Feature{Name: "pkg1", Version: "1", VersionFormat: "rpm", Type: database.BinaryPackage},
						By:      database.Detector{Name: redhatrpm.Name},
					},
				}}},
				// send layer with Red Hat pkg and namespace which should be shared with previous layer
				&database.LayerScanResult{NewScanResultLayer: &database.Layer{Hash: "sha:222", Features: []database.LayerFeature{
					database.LayerFeature{
						Feature:            redhatrpm.NamespaceHolderPackage,
						By:                 database.Detector{Name: redhatrpm.Name},
						PotentialNamespace: database.Namespace{Name: "cpe:/o:redhat:enterprise_linux:7::computenode", VersionFormat: rpm.ParserName},
					},
					database.LayerFeature{
						Feature:            database.Feature{Name: "pkg2", Version: "1", VersionFormat: "rpm", Type: database.BinaryPackage},
						By:                 database.Detector{Name: redhatrpm.Name},
						PotentialNamespace: database.Namespace{Name: "cpe:/o:redhat:enterprise_linux:7::computenode", VersionFormat: rpm.ParserName},
					},
				}}},
				// Another layer with Red Hat's content
				&database.LayerScanResult{NewScanResultLayer: &database.Layer{Hash: "sha:333", Features: []database.LayerFeature{
					database.LayerFeature{
						Feature:            redhatrpm.NamespaceHolderPackage,
						By:                 database.Detector{Name: redhatrpm.Name},
						PotentialNamespace: database.Namespace{Name: "cpe:/o:redhat:enterprise_linux:8::computenode", VersionFormat: rpm.ParserName},
					},
					database.LayerFeature{
						Feature:            database.Feature{Name: "pkg3", Version: "1", VersionFormat: "rpm", Type: database.BinaryPackage},
						By:                 database.Detector{Name: redhatrpm.Name},
						PotentialNamespace: database.Namespace{Name: "cpe:/o:redhat:enterprise_linux:8::computenode", VersionFormat: rpm.ParserName},
					},
				}}},
				// Third party layer with Red Hat's content but with missing namepace - namespace will be shared from previous layer
				&database.LayerScanResult{NewScanResultLayer: &database.Layer{Hash: "sha:444", Features: []database.LayerFeature{
					database.LayerFeature{
						Feature: database.Feature{Name: "pkg4", Version: "1", VersionFormat: "rpm", Type: database.BinaryPackage},
						By:      database.Detector{Name: redhatrpm.Name},
					},
					database.LayerFeature{
						Feature: database.Feature{Name: "other-vendor-2", Version: "1", VersionFormat: "apk", Type: database.BinaryPackage},
						By:      database.Detector{Name: "apk"},
					},
				}}},
			},
			[]*database.LayerScanResult{
				&database.LayerScanResult{NewScanResultLayer: &database.Layer{Hash: "sha:111", Features: []database.LayerFeature{
					database.LayerFeature{
						Feature:            database.Feature{Name: "pkg1", Version: "1", VersionFormat: "rpm", Type: database.BinaryPackage},
						By:                 database.Detector{Name: redhatrpm.Name},
						PotentialNamespace: database.Namespace{Name: "cpe:/o:redhat:enterprise_linux:7::computenode", VersionFormat: rpm.ParserName},
					},
				}}},
				&database.LayerScanResult{NewScanResultLayer: &database.Layer{Hash: "sha:222", Features: []database.LayerFeature{
					database.LayerFeature{
						Feature:            database.Feature{Name: "pkg2", Version: "1", VersionFormat: "rpm", Type: database.BinaryPackage},
						By:                 database.Detector{Name: redhatrpm.Name},
						PotentialNamespace: database.Namespace{Name: "cpe:/o:redhat:enterprise_linux:7::computenode", VersionFormat: rpm.ParserName},
					},
				}}},
				&database.LayerScanResult{NewScanResultLayer: &database.Layer{Hash: "sha:333", Features: []database.LayerFeature{
					database.LayerFeature{
						Feature:            database.Feature{Name: "pkg3", Version: "1", VersionFormat: "rpm", Type: database.BinaryPackage},
						By:                 database.Detector{Name: redhatrpm.Name},
						PotentialNamespace: database.Namespace{Name: "cpe:/o:redhat:enterprise_linux:8::computenode", VersionFormat: rpm.ParserName},
					},
				}}},
				&database.LayerScanResult{NewScanResultLayer: &database.Layer{Hash: "sha:444", Features: []database.LayerFeature{
					database.LayerFeature{
						Feature: database.Feature{Name: "other-vendor-2", Version: "1", VersionFormat: "apk", Type: database.BinaryPackage},
						By:      database.Detector{Name: "apk"},
					},
					database.LayerFeature{
						Feature:            database.Feature{Name: "pkg4", Version: "1", VersionFormat: "rpm", Type: database.BinaryPackage},
						By:                 database.Detector{Name: redhatrpm.Name},
						PotentialNamespace: database.Namespace{Name: "cpe:/o:redhat:enterprise_linux:8::computenode", VersionFormat: rpm.ParserName},
					},
				}}},
			},
		},
		// image with no Red Hat's content
		{
			[]*database.LayerScanResult{
				&database.LayerScanResult{NewScanResultLayer: &database.Layer{Hash: "sha:111", Features: []database.LayerFeature{

					database.LayerFeature{
						Feature: database.Feature{Name: "other-vendor-2", Version: "1", VersionFormat: "apk", Type: database.BinaryPackage},
						By:      database.Detector{Name: "apk"},
					},
				}}},
			},
			[]*database.LayerScanResult{
				&database.LayerScanResult{NewScanResultLayer: &database.Layer{Hash: "sha:111", Features: []database.LayerFeature{
					database.LayerFeature{
						Feature: database.Feature{Name: "other-vendor-2", Version: "1", VersionFormat: "apk", Type: database.BinaryPackage},
						By:      database.Detector{Name: "apk"},
					},
				}}},
			},
		},
	} {
		postProcessor := &postProcessor{}
		result, err := postProcessor.PostProcessImage(test.layers)

		require.Equal(t, err, nil)
		require.Equal(t, test.expectedResult, result)
	}
}
