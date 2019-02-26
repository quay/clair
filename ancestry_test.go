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
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/coreos/clair/database"
)

var (
	dpkg      = database.NewFeatureDetector("dpkg", "1.0")
	rpm       = database.NewFeatureDetector("rpm", "1.0")
	pip       = database.NewFeatureDetector("pip", "1.0")
	python    = database.NewNamespaceDetector("python", "1.0")
	osrelease = database.NewNamespaceDetector("os-release", "1.0")
	ubuntu    = *database.NewNamespace("ubuntu:14.04", "dpkg")
	ubuntu16  = *database.NewNamespace("ubuntu:16.04", "dpkg")
	python2   = *database.NewNamespace("python:2", "pip")
	sed       = *database.NewSourcePackage("sed", "4.4-2", "dpkg")
	sedBin    = *database.NewBinaryPackage("sed", "4.4-2", "dpkg")
	tar       = *database.NewBinaryPackage("tar", "1.29b-2", "dpkg")
	scipy     = *database.NewSourcePackage("scipy", "3.0.0", "pip")

	detectors               = []database.Detector{dpkg, osrelease, rpm}
	multinamespaceDetectors = []database.Detector{dpkg, osrelease, pip}
)

// layerBuilder is for helping constructing the layer test artifacts.
type layerBuilder struct {
	layer *database.Layer
}

func newLayerBuilder(hash string) *layerBuilder {
	return &layerBuilder{&database.Layer{Hash: hash, By: detectors}}
}

func (b *layerBuilder) addNamespace(detector database.Detector, ns database.Namespace) *layerBuilder {
	b.layer.Namespaces = append(b.layer.Namespaces, database.LayerNamespace{
		Namespace: ns,
		By:        detector,
	})
	return b
}

func (b *layerBuilder) addFeature(detector database.Detector, f database.Feature) *layerBuilder {
	b.layer.Features = append(b.layer.Features, database.LayerFeature{
		Feature: f,
		By:      detector,
	})

	return b
}

var testImage = []*database.Layer{
	// empty layer
	newLayerBuilder("0").layer,
	// ubuntu namespace
	newLayerBuilder("1").addNamespace(osrelease, ubuntu).layer,
	// install sed
	newLayerBuilder("2").addFeature(dpkg, sed).layer,
	// install tar
	newLayerBuilder("3").addFeature(dpkg, sed).addFeature(dpkg, tar).layer,
	// remove tar
	newLayerBuilder("4").addFeature(dpkg, sed).layer,
	// upgrade ubuntu
	newLayerBuilder("5").addNamespace(osrelease, ubuntu16).layer,
	// no change to the detectable files
	newLayerBuilder("6").layer,
	// change to the package installer database but no features are affected.
	newLayerBuilder("7").addFeature(dpkg, sed).layer,
}

var clairLimit = []*database.Layer{
	// TODO(sidac): how about install rpm package under ubuntu?
	newLayerBuilder("1").addNamespace(osrelease, ubuntu).layer,
	newLayerBuilder("2").addFeature(rpm, sed).layer,
}

var multipleNamespace = []*database.Layer{
	// TODO(sidac): support for multiple namespaces
}

var invalidNamespace = []*database.Layer{
	// add package without namespace, this indicates that the namespace detector
	// could not detect the namespace.
	newLayerBuilder("0").addFeature(dpkg, sed).layer,
}

var multiplePackagesOnFirstLayer = []*database.Layer{
	newLayerBuilder("0").addFeature(dpkg, sed).addFeature(dpkg, tar).addFeature(dpkg, sedBin).addNamespace(osrelease, ubuntu16).layer,
}

func TestAddLayer(t *testing.T) {
	cases := []struct {
		title string
		image []*database.Layer

		expectedAncestry database.Ancestry
	}{
		{
			title:            "empty image",
			expectedAncestry: database.Ancestry{Name: ancestryName([]string{}), By: detectors},
		},
		{
			title:            "empty layer",
			image:            testImage[:1],
			expectedAncestry: database.Ancestry{Name: ancestryName([]string{"0"}), By: detectors, Layers: []database.AncestryLayer{{Hash: "0"}}},
		},
		{
			title: "ubuntu",
			image: testImage[:2],
			expectedAncestry: database.Ancestry{
				Name:   ancestryName([]string{"0", "1"}),
				By:     detectors,
				Layers: []database.AncestryLayer{{Hash: "0"}, {Hash: "1"}},
			},
		},
		{
			title: "ubuntu install sed",
			image: testImage[:3],
			expectedAncestry: database.Ancestry{
				Name: ancestryName([]string{"0", "1", "2"}),
				By:   detectors,
				Layers: []database.AncestryLayer{{Hash: "0"}, {Hash: "1"}, {Hash: "2", Features: []database.AncestryFeature{
					{
						NamespacedFeature: database.NamespacedFeature{Feature: sed, Namespace: ubuntu},
						FeatureBy:         dpkg,
						NamespaceBy:       osrelease,
					},
				}}},
			},
		},
		{
			title: "ubuntu install tar",
			image: testImage[:4],
			expectedAncestry: database.Ancestry{
				Name: ancestryName([]string{"0", "1", "2", "3"}),
				By:   detectors,
				Layers: []database.AncestryLayer{{Hash: "0"}, {Hash: "1"}, {Hash: "2", Features: []database.AncestryFeature{
					{
						NamespacedFeature: database.NamespacedFeature{Feature: sed, Namespace: ubuntu},
						FeatureBy:         dpkg,
						NamespaceBy:       osrelease,
					},
				}}, {
					Hash: "3", Features: []database.AncestryFeature{
						{
							NamespacedFeature: database.NamespacedFeature{Feature: tar, Namespace: ubuntu},
							FeatureBy:         dpkg,
							NamespaceBy:       osrelease,
						},
					},
				}},
			},
		}, {
			title: "ubuntu uninstall tar",
			image: testImage[:5],
			expectedAncestry: database.Ancestry{
				Name: ancestryName([]string{"0", "1", "2", "3", "4"}),
				By:   detectors,
				Layers: []database.AncestryLayer{{Hash: "0"}, {Hash: "1"}, {Hash: "2", Features: []database.AncestryFeature{
					{
						NamespacedFeature: database.NamespacedFeature{Feature: sed, Namespace: ubuntu},
						FeatureBy:         dpkg,
						NamespaceBy:       osrelease,
					},
				}}, {Hash: "3"}, {Hash: "4"}},
			},
		}, {
			title: "ubuntu upgrade",
			image: testImage[:6],
			expectedAncestry: database.Ancestry{
				Name: ancestryName([]string{"0", "1", "2", "3", "4", "5"}),
				By:   detectors,
				Layers: []database.AncestryLayer{{Hash: "0"}, {Hash: "1"}, {Hash: "2"}, {Hash: "3"}, {Hash: "4"}, {Hash: "5", Features: []database.AncestryFeature{
					{
						NamespacedFeature: database.NamespacedFeature{Feature: sed, Namespace: ubuntu16},
						FeatureBy:         dpkg,
						NamespaceBy:       osrelease,
					}}},
				},
			},
		}, {
			title: "no change to the detectable files",
			image: testImage[:7],
			expectedAncestry: database.Ancestry{
				Name: ancestryName([]string{"0", "1", "2", "3", "4", "5", "6"}),
				By:   detectors,
				Layers: []database.AncestryLayer{{Hash: "0"}, {Hash: "1"}, {Hash: "2"}, {Hash: "3"}, {Hash: "4"}, {Hash: "5", Features: []database.AncestryFeature{
					{
						NamespacedFeature: database.NamespacedFeature{Feature: sed, Namespace: ubuntu16},
						FeatureBy:         dpkg,
						NamespaceBy:       osrelease,
					}}}, {Hash: "6"}},
			},
		}, {
			title: "change to the package installer database but no features are affected.",
			image: testImage[:8],
			expectedAncestry: database.Ancestry{
				Name: ancestryName([]string{"0", "1", "2", "3", "4", "5", "6", "7"}),
				By:   detectors,
				Layers: []database.AncestryLayer{{Hash: "0"}, {Hash: "1"}, {Hash: "2"}, {Hash: "3"}, {Hash: "4"}, {Hash: "5", Features: []database.AncestryFeature{
					{
						NamespacedFeature: database.NamespacedFeature{Feature: sed, Namespace: ubuntu16},
						FeatureBy:         dpkg,
						NamespaceBy:       osrelease,
					}}}, {Hash: "6"}, {Hash: "7"}},
			},
		}, {
			title: "layers with features and namespace.",
			image: multiplePackagesOnFirstLayer,
			expectedAncestry: database.Ancestry{
				Name: ancestryName([]string{"0"}),
				By:   detectors,
				Layers: []database.AncestryLayer{
					{
						Hash: "0",
						Features: []database.AncestryFeature{
							{
								NamespacedFeature: database.NamespacedFeature{Feature: sed, Namespace: ubuntu16},
								FeatureBy:         dpkg,
								NamespaceBy:       osrelease,
							},
							{
								NamespacedFeature: database.NamespacedFeature{Feature: sedBin, Namespace: ubuntu16},
								FeatureBy:         dpkg,
								NamespaceBy:       osrelease,
							},
							{
								NamespacedFeature: database.NamespacedFeature{Feature: tar, Namespace: ubuntu16},
								FeatureBy:         dpkg,
								NamespaceBy:       osrelease,
							},
						},
					},
				},
			},
		},
	}

	for _, test := range cases {
		t.Run(test.title, func(t *testing.T) {
			builder := NewAncestryBuilder(detectors)
			for _, layer := range test.image {
				builder.AddLeafLayer(layer)
			}

			ancestry := builder.Ancestry("")
			require.True(t, database.AssertAncestryEqual(t, &test.expectedAncestry, ancestry))
		})
	}
}
