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
	dpkg       = database.NewFeatureDetector("dpkg", "1.0")
	rpm        = database.NewFeatureDetector("rpm", "1.0")
	pip        = database.NewFeatureDetector("pip", "1.0")
	python     = database.NewNamespaceDetector("python", "1.0")
	osrelease  = database.NewNamespaceDetector("os-release", "1.0")
	aptsources = database.NewNamespaceDetector("apt-sources", "1.0")
	ubuntu     = *database.NewNamespace("ubuntu:14.04", "dpkg")
	ubuntu16   = *database.NewNamespace("ubuntu:16.04", "dpkg")
	rhel7      = *database.NewNamespace("cpe:/o:redhat:enterprise_linux:7::computenode", "rpm")
	debian     = *database.NewNamespace("debian:7", "dpkg")
	python2    = *database.NewNamespace("python:2", "pip")
	sed        = *database.NewSourcePackage("sed", "4.4-2", "dpkg")
	sedByRPM   = *database.NewBinaryPackage("sed", "4.4-2", "rpm")
	sedBin     = *database.NewBinaryPackage("sed", "4.4-2", "dpkg")
	tar        = *database.NewBinaryPackage("tar", "1.29b-2", "dpkg")
	scipy      = *database.NewSourcePackage("scipy", "3.0.0", "pip")

	emptyNamespace = database.Namespace{}

	detectors               = []database.Detector{dpkg, osrelease, rpm}
	multinamespaceDetectors = []database.Detector{dpkg, osrelease, pip}
)

type ancestryBuilder struct {
	ancestry *database.Ancestry
}

func newAncestryBuilder(name string) *ancestryBuilder {
	return &ancestryBuilder{&database.Ancestry{Name: name}}
}

func (b *ancestryBuilder) addDetectors(d ...database.Detector) *ancestryBuilder {
	b.ancestry.By = append(b.ancestry.By, d...)
	return b
}

func (b *ancestryBuilder) addLayer(hash string, f ...database.AncestryFeature) *ancestryBuilder {
	l := database.AncestryLayer{Hash: hash}
	l.Features = append(l.Features, f...)
	b.ancestry.Layers = append(b.ancestry.Layers, l)
	return b
}

func ancestryFeature(namespace database.Namespace, feature database.Feature, nsBy database.Detector, fBy database.Detector) database.AncestryFeature {
	return database.AncestryFeature{
		NamespacedFeature: database.NamespacedFeature{feature, namespace},
		FeatureBy:         fBy,
		NamespaceBy:       nsBy,
	}
}

// layerBuilder is for helping constructing the layer test artifacts.
type layerBuilder struct {
	layer *database.Layer
}

func newLayerBuilder(hash string) *layerBuilder {
	return &layerBuilder{&database.Layer{Hash: hash, By: detectors}}
}

func newLayerBuilderWithoutDetector(hash string) *layerBuilder {
	return &layerBuilder{&database.Layer{Hash: hash}}
}

func (b *layerBuilder) addDetectors(d ...database.Detector) *layerBuilder {
	b.layer.By = append(b.layer.By, d...)
	return b
}

func (b *layerBuilder) addNamespace(detector database.Detector, ns database.Namespace) *layerBuilder {
	b.layer.Namespaces = append(b.layer.Namespaces, database.LayerNamespace{
		Namespace: ns,
		By:        detector,
	})
	return b
}

func (b *layerBuilder) addFeature(detector database.Detector, f database.Feature, ns database.Namespace) *layerBuilder {
	b.layer.Features = append(b.layer.Features, database.LayerFeature{
		Feature:            f,
		By:                 detector,
		PotentialNamespace: ns,
	})

	return b
}

var testImage = []*database.Layer{
	// empty layer
	newLayerBuilder("0").layer,
	// ubuntu namespace
	newLayerBuilder("1").addNamespace(osrelease, ubuntu).layer,
	// install sed
	newLayerBuilder("2").addFeature(dpkg, sed, emptyNamespace).layer,
	// install tar
	newLayerBuilder("3").addFeature(dpkg, sed, emptyNamespace).addFeature(dpkg, tar, emptyNamespace).layer,
	// remove tar
	newLayerBuilder("4").addFeature(dpkg, sed, emptyNamespace).layer,
	// upgrade ubuntu
	newLayerBuilder("5").addNamespace(osrelease, ubuntu16).layer,
	// no change to the detectable files
	newLayerBuilder("6").layer,
	// change to the package installer database but no features are affected.
	newLayerBuilder("7").addFeature(dpkg, sed, emptyNamespace).layer,
}

var invalidNamespace = []*database.Layer{
	// add package without namespace, this indicates that the namespace detector
	// could not detect the namespace.
	newLayerBuilder("0").addFeature(dpkg, sed, emptyNamespace).layer,
}

var noMatchingNamespace = []*database.Layer{
	newLayerBuilder("0").addFeature(rpm, sedByRPM, emptyNamespace).addFeature(dpkg, sed, emptyNamespace).addNamespace(osrelease, ubuntu).layer,
}

var multiplePackagesOnFirstLayer = []*database.Layer{
	newLayerBuilder("0").addFeature(dpkg, sed, emptyNamespace).addFeature(dpkg, tar, emptyNamespace).addFeature(dpkg, sedBin, emptyNamespace).addNamespace(osrelease, ubuntu16).layer,
}

var twoNamespaceDetectorsWithSameResult = []*database.Layer{
	newLayerBuilderWithoutDetector("0").addDetectors(dpkg, aptsources, osrelease).addFeature(dpkg, sed, emptyNamespace).addNamespace(aptsources, ubuntu).addNamespace(osrelease, ubuntu).layer,
}

var sameVersionFormatDiffName = []*database.Layer{
	newLayerBuilder("0").addFeature(dpkg, sed, emptyNamespace).addNamespace(aptsources, ubuntu).addNamespace(osrelease, debian).layer,
}

var potentialFeatureNamespace = []*database.Layer{
	newLayerBuilder("0").addFeature(rpm, sed, rhel7).layer,
}

func TestAddLayer(t *testing.T) {
	cases := []struct {
		title               string
		image               []*database.Layer
		nonDefaultDetectors []database.Detector
		expectedAncestry    database.Ancestry
	}{
		{
			title:            "empty image",
			expectedAncestry: *newAncestryBuilder(ancestryName([]string{})).addDetectors(detectors...).ancestry,
		},
		{
			title: "empty layer",
			image: testImage[:1],
			expectedAncestry: *newAncestryBuilder(ancestryName([]string{"0"})).addDetectors(detectors...).
				addLayer("0").ancestry,
		},
		{
			title: "ubuntu",
			image: testImage[:2],
			expectedAncestry: *newAncestryBuilder(ancestryName([]string{"0", "1"})).addDetectors(detectors...).
				addLayer("0").
				addLayer("1").ancestry,
		},
		{
			title: "ubuntu install sed",
			image: testImage[:3],
			expectedAncestry: *newAncestryBuilder(ancestryName([]string{"0", "1", "2"})).addDetectors(detectors...).
				addLayer("0").
				addLayer("1").
				addLayer("2", ancestryFeature(ubuntu, sed, osrelease, dpkg)).ancestry,
		},
		{
			title: "ubuntu install tar",
			image: testImage[:4],
			expectedAncestry: *newAncestryBuilder(ancestryName([]string{"0", "1", "2", "3"})).addDetectors(detectors...).
				addLayer("0").
				addLayer("1").
				addLayer("2", ancestryFeature(ubuntu, sed, osrelease, dpkg)).
				addLayer("3", ancestryFeature(ubuntu, tar, osrelease, dpkg)).ancestry,
		}, {
			title: "ubuntu uninstall tar",
			image: testImage[:5],
			expectedAncestry: *newAncestryBuilder(ancestryName([]string{"0", "1", "2", "3", "4"})).addDetectors(detectors...).
				addLayer("0").
				addLayer("1").
				addLayer("2", ancestryFeature(ubuntu, sed, osrelease, dpkg)).
				addLayer("3").
				addLayer("4").ancestry,
		}, {
			title: "ubuntu upgrade",
			image: testImage[:6],
			expectedAncestry: *newAncestryBuilder(ancestryName([]string{"0", "1", "2", "3", "4", "5"})).addDetectors(detectors...).
				addLayer("0").
				addLayer("1").
				addLayer("2").
				addLayer("3").
				addLayer("4").
				addLayer("5", ancestryFeature(ubuntu16, sed, osrelease, dpkg)).ancestry,
		}, {
			title: "no change to the detectable files",
			image: testImage[:7],
			expectedAncestry: *newAncestryBuilder(ancestryName([]string{"0", "1", "2", "3", "4", "5", "6"})).addDetectors(detectors...).
				addLayer("0").
				addLayer("1").
				addLayer("2").
				addLayer("3").
				addLayer("4").
				addLayer("5", ancestryFeature(ubuntu16, sed, osrelease, dpkg)).
				addLayer("6").ancestry,
		}, {
			title: "change to the package installer database but no features are affected.",
			image: testImage[:8],
			expectedAncestry: *newAncestryBuilder(ancestryName([]string{"0", "1", "2", "3", "4", "5", "6", "7"})).addDetectors(detectors...).
				addLayer("0").
				addLayer("1").
				addLayer("2").
				addLayer("3").
				addLayer("4").
				addLayer("5", ancestryFeature(ubuntu16, sed, osrelease, dpkg)).
				addLayer("6").
				addLayer("7").ancestry,
		}, {
			title: "layers with features and namespace.",
			image: multiplePackagesOnFirstLayer,
			expectedAncestry: *newAncestryBuilder(ancestryName([]string{"0"})).addDetectors(detectors...).
				addLayer("0",
					ancestryFeature(ubuntu16, sed, osrelease, dpkg),
					ancestryFeature(ubuntu16, sedBin, osrelease, dpkg),
					ancestryFeature(ubuntu16, tar, osrelease, dpkg)).
				ancestry,
		}, {
			title:               "two namespace detectors giving same namespace.",
			image:               twoNamespaceDetectorsWithSameResult,
			nonDefaultDetectors: []database.Detector{osrelease, aptsources, dpkg},
			expectedAncestry: *newAncestryBuilder(ancestryName([]string{"0"})).addDetectors(osrelease, aptsources, dpkg).
				addLayer("0", ancestryFeature(ubuntu, sed, aptsources, dpkg)).
				ancestry,
		}, {
			title: "feature without namespace",
			image: invalidNamespace,
			expectedAncestry: *newAncestryBuilder(ancestryName([]string{"0"})).addDetectors(detectors...).
				addLayer("0").
				ancestry,
		}, {
			title: "two namespaces with the same version format but different names",
			image: sameVersionFormatDiffName,
			// failure of matching a namespace will result in the package not being added.
			expectedAncestry: *newAncestryBuilder(ancestryName([]string{"0"})).addDetectors(detectors...).
				addLayer("0").
				ancestry,
		}, {
			title:            "noMatchingNamespace",
			image:            noMatchingNamespace,
			expectedAncestry: *newAncestryBuilder(ancestryName([]string{"0"})).addDetectors(detectors...).addLayer("0", ancestryFeature(ubuntu, sed, osrelease, dpkg)).ancestry,
		}, {
			title:            "featureWithPotentialNamespace",
			image:            potentialFeatureNamespace,
			expectedAncestry: *newAncestryBuilder(ancestryName([]string{"0"})).addDetectors(detectors...).addLayer("0", ancestryFeature(rhel7, sed, database.Detector{}, rpm)).ancestry,
		},
	}

	for _, test := range cases {
		t.Run(test.title, func(t *testing.T) {
			var builder *AncestryBuilder
			if len(test.nonDefaultDetectors) != 0 {
				builder = NewAncestryBuilder(test.nonDefaultDetectors)
			} else {
				builder = NewAncestryBuilder(detectors)
			}

			for _, layer := range test.image {
				builder.AddLeafLayer(layer)
			}

			ancestry := builder.Ancestry("")
			require.True(t, database.AssertAncestryEqual(t, &test.expectedAncestry, ancestry))
		})
	}
}
