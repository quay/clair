// Copyright 2017 clair authors
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
	"errors"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/ext/featurefmt"
	"github.com/coreos/clair/ext/featurens"
	"github.com/coreos/clair/ext/versionfmt/dpkg"

	// Register the required detectors.
	_ "github.com/coreos/clair/ext/featurefmt/dpkg"
	_ "github.com/coreos/clair/ext/featurefmt/rpm"
	_ "github.com/coreos/clair/ext/featurens/aptsources"
	_ "github.com/coreos/clair/ext/featurens/osrelease"
	_ "github.com/coreos/clair/ext/imagefmt/docker"
)

type mockDatastore struct {
	database.MockDatastore

	layers             map[string]database.Layer
	ancestry           map[string]database.Ancestry
	namespaces         map[string]database.Namespace
	features           map[string]database.Feature
	namespacedFeatures map[string]database.NamespacedFeature
}

type mockSession struct {
	database.MockSession

	store      *mockDatastore
	copy       mockDatastore
	terminated bool
}

func copyDatastore(md *mockDatastore) mockDatastore {
	layers := map[string]database.Layer{}
	for k, l := range md.layers {
		layers[k] = database.Layer{
			Hash:       l.Hash,
			By:         append([]database.Detector{}, l.By...),
			Features:   append([]database.LayerFeature{}, l.Features...),
			Namespaces: append([]database.LayerNamespace{}, l.Namespaces...),
		}
	}

	ancestry := map[string]database.Ancestry{}
	for k, a := range md.ancestry {
		ancestryLayers := []database.AncestryLayer{}
		for _, layer := range a.Layers {
			ancestryLayers = append(ancestryLayers, database.AncestryLayer{
				Hash:     layer.Hash,
				Features: append([]database.AncestryFeature{}, layer.Features...),
			})
		}

		ancestry[k] = database.Ancestry{
			Name:   a.Name,
			By:     append([]database.Detector{}, a.By...),
			Layers: ancestryLayers,
		}
	}

	namespaces := map[string]database.Namespace{}
	for k, n := range md.namespaces {
		namespaces[k] = n
	}

	features := map[string]database.Feature{}
	for k, f := range md.features {
		features[k] = f
	}

	namespacedFeatures := map[string]database.NamespacedFeature{}
	for k, f := range md.namespacedFeatures {
		namespacedFeatures[k] = f
	}

	return mockDatastore{
		layers:             layers,
		ancestry:           ancestry,
		namespaces:         namespaces,
		namespacedFeatures: namespacedFeatures,
		features:           features,
	}
}

func newMockDatastore() *mockDatastore {
	errSessionDone := errors.New("Session Done")
	md := &mockDatastore{
		layers:             make(map[string]database.Layer),
		ancestry:           make(map[string]database.Ancestry),
		namespaces:         make(map[string]database.Namespace),
		features:           make(map[string]database.Feature),
		namespacedFeatures: make(map[string]database.NamespacedFeature),
	}

	md.FctBegin = func() (database.Session, error) {
		session := &mockSession{
			store:      md,
			copy:       copyDatastore(md),
			terminated: false,
		}

		session.FctCommit = func() error {
			if session.terminated {
				return nil
			}
			session.store.layers = session.copy.layers
			session.store.ancestry = session.copy.ancestry
			session.store.namespaces = session.copy.namespaces
			session.store.features = session.copy.features
			session.store.namespacedFeatures = session.copy.namespacedFeatures
			session.terminated = true
			return nil
		}

		session.FctRollback = func() error {
			if session.terminated {
				return nil
			}
			session.terminated = true
			session.copy = mockDatastore{}
			return nil
		}

		session.FctFindAncestry = func(name string) (database.Ancestry, bool, error) {
			if session.terminated {
				return database.Ancestry{}, false, errSessionDone
			}
			ancestry, ok := session.copy.ancestry[name]
			return ancestry, ok, nil
		}

		session.FctFindLayer = func(name string) (database.Layer, bool, error) {
			if session.terminated {
				return database.Layer{}, false, errSessionDone
			}
			layer, ok := session.copy.layers[name]
			return layer, ok, nil
		}

		session.FctPersistNamespaces = func(ns []database.Namespace) error {
			if session.terminated {
				return errSessionDone
			}
			for _, n := range ns {
				session.copy.namespaces[NamespaceKey(&n)] = n
			}
			return nil
		}

		session.FctPersistFeatures = func(fs []database.Feature) error {
			if session.terminated {
				return errSessionDone
			}
			for _, f := range fs {
				session.copy.features[FeatureKey(&f)] = f
			}

			return nil
		}

		session.FctPersistLayer = func(hash string, features []database.LayerFeature, namespaces []database.LayerNamespace, by []database.Detector) error {
			if session.terminated {
				return errSessionDone
			}

			for _, ns := range namespaces {
				if _, ok := session.copy.namespaces[NamespaceKey(&ns.Namespace)]; !ok {
					panic("")
				}
			}

			for _, f := range features {
				if _, ok := session.copy.features[FeatureKey(&f.Feature)]; !ok {
					panic("")
				}
			}

			layer, _ := session.copy.layers[hash]
			database.MergeLayers(&layer, &database.Layer{
				Hash:       hash,
				By:         by,
				Namespaces: namespaces,
				Features:   features,
			})

			session.copy.layers[hash] = layer
			return nil
		}

		session.FctUpsertAncestry = func(ancestry database.Ancestry) error {
			if session.terminated {
				return errSessionDone
			}

			// ensure the namespaces features are in the code base
			for _, l := range ancestry.Layers {
				for _, f := range l.GetFeatures() {
					if _, ok := session.copy.namespacedFeatures[NamespacedFeatureKey(&f)]; !ok {
						panic("")
					}
				}
			}

			session.copy.ancestry[ancestry.Name] = ancestry
			return nil
		}

		session.FctPersistNamespacedFeatures = func(namespacedFeatures []database.NamespacedFeature) error {
			for i, f := range namespacedFeatures {
				if _, ok := session.copy.features[FeatureKey(&f.Feature)]; !ok {
					panic("")
				}

				if _, ok := session.copy.namespaces[NamespaceKey(&f.Namespace)]; !ok {
					panic("")
				}

				session.copy.namespacedFeatures[NamespacedFeatureKey(&f)] = namespacedFeatures[i]
			}
			return nil
		}

		session.FctCacheAffectedNamespacedFeatures = func(namespacedFeatures []database.NamespacedFeature) error {
			// The function does nothing because we don't care about the vulnerability cache in worker_test.
			return nil
		}

		return session, nil
	}
	return md
}

func TestMain(m *testing.M) {
	EnabledDetectors = append(featurefmt.ListListers(), featurens.ListDetectors()...)
	m.Run()
}

func FeatureKey(f *database.Feature) string {
	return strings.Join([]string{f.Name, f.VersionFormat, f.Version}, "__")
}

func NamespaceKey(ns *database.Namespace) string {
	return strings.Join([]string{ns.Name, ns.VersionFormat}, "__")
}

func NamespacedFeatureKey(f *database.NamespacedFeature) string {
	return strings.Join([]string{f.Name, f.Namespace.Name}, "__")
}

func TestProcessAncestryWithDistUpgrade(t *testing.T) {
	// TODO(sidac): Change to use table driven tests.
	// Create the list of Features that should not been upgraded from one layer to another.
	nonUpgradedFeatures := []database.Feature{
		{Name: "libtext-wrapi18n-perl", Version: "0.06-7", SourceName: "libtext", SourceVersion: "0.06-7"},
		{Name: "libtext-charwidth-perl", Version: "0.04-7", SourceName: "libtext", SourceVersion: "0.04-7"},
		{Name: "libtext-iconv-perl", Version: "1.7-5", SourceName: "libtext", SourceVersion: "1.7-5"},
		{Name: "mawk", Version: "1.3.3-17", SourceName: "mawk", SourceVersion: "1.3.3-17"},
		{Name: "insserv", Version: "1.14.0-5", SourceName: "insserv", SourceVersion: "1.14.0-5"},
		{Name: "db", Version: "5.1.29-5", SourceName: "db", SourceVersion: "5.1.29-5"},
		{Name: "ustr", Version: "1.0.4-3", SourceName: "ustr", SourceVersion: "1.0.4-3"},
		{Name: "xz-utils", Version: "5.1.1alpha+20120614-2", SourceName: "xz", SourceVersion: "5.1.1alpha+20120614-2"},
	}

	nonUpgradedMap := map[database.Feature]struct{}{}
	for _, f := range nonUpgradedFeatures {
		f.VersionFormat = "dpkg"
		nonUpgradedMap[f] = struct{}{}
	}

	// Process test layers.
	//
	// blank.tar: MAINTAINER Quentin MACHU <quentin.machu.fr>
	// wheezy.tar: FROM debian:wheezy
	// jessie.tar: RUN sed -i "s/precise/trusty/" /etc/apt/sources.list && apt-get update &&
	//             apt-get -y dist-upgrade
	_, f, _, _ := runtime.Caller(0)
	testDataPath := filepath.Join(filepath.Dir(f)) + "/testdata/DistUpgrade/"

	datastore := newMockDatastore()

	layers := []LayerRequest{
		{Hash: "blank", Path: testDataPath + "blank.tar.gz"},
		{Hash: "wheezy", Path: testDataPath + "wheezy.tar.gz"},
		{Hash: "jessie", Path: testDataPath + "jessie.tar.gz"},
	}

	assert.Nil(t, ProcessAncestry(datastore, "Docker", "Mock", layers))

	// check the ancestry features
	features := []database.AncestryFeature{}
	for i, l := range datastore.ancestry["Mock"].Layers {
		assert.Equal(t, layers[i].Hash, l.Hash)
		features = append(features, l.Features...)
	}

	assert.Len(t, features, 117)
	for _, f := range features {
		if _, ok := nonUpgradedMap[f.Feature]; ok {
			assert.Equal(t, "debian:7", f.Namespace.Name)
		} else {
			assert.Equal(t, "debian:8", f.Namespace.Name)
		}
	}
}

func TestProcessLayers(t *testing.T) {
	_, f, _, _ := runtime.Caller(0)
	testDataPath := filepath.Join(filepath.Dir(f)) + "/testdata/DistUpgrade/"

	datastore := newMockDatastore()

	layers := []LayerRequest{
		{Hash: "blank", Path: testDataPath + "blank.tar.gz"},
		{Hash: "wheezy", Path: testDataPath + "wheezy.tar.gz"},
		{Hash: "jessie", Path: testDataPath + "jessie.tar.gz"},
	}

	LayerWithContents, err := processLayers(datastore, "Docker", layers)
	assert.Nil(t, err)
	assert.Len(t, LayerWithContents, 3)
	// ensure resubmit won't break the stuff
	LayerWithContents, err = processLayers(datastore, "Docker", layers)
	assert.Nil(t, err)
	assert.Len(t, LayerWithContents, 3)
	// Ensure each processed layer is correct
	assert.Len(t, LayerWithContents[0].Namespaces, 0)
	assert.Len(t, LayerWithContents[1].Namespaces, 1)
	assert.Len(t, LayerWithContents[2].Namespaces, 1)
	assert.Len(t, LayerWithContents[0].Features, 0)
	assert.Len(t, LayerWithContents[1].Features, 80)
	assert.Len(t, LayerWithContents[2].Features, 117)

	// Ensure each layer has expected namespaces and features detected
	if blank, ok := datastore.layers["blank"]; ok {
		database.AssertDetectorsEqual(t, EnabledDetectors, blank.By)
		assert.Len(t, blank.Namespaces, 0)
		assert.Len(t, blank.Features, 0)
	} else {
		assert.Fail(t, "blank is not stored")
		return
	}

	if wheezy, ok := datastore.layers["wheezy"]; ok {
		database.AssertDetectorsEqual(t, EnabledDetectors, wheezy.By)
		assert.Equal(t, []database.LayerNamespace{
			{database.Namespace{"debian:7", dpkg.ParserName}, database.NewNamespaceDetector("os-release", "1.0")},
		}, wheezy.Namespaces)

		assert.Len(t, wheezy.Features, 80)
	} else {
		assert.Fail(t, "wheezy is not stored")
		return
	}

	if jessie, ok := datastore.layers["jessie"]; ok {
		database.AssertDetectorsEqual(t, EnabledDetectors, jessie.By)
		assert.Equal(t, []database.LayerNamespace{
			{database.Namespace{"debian:8", dpkg.ParserName}, database.NewNamespaceDetector("os-release", "1.0")},
		}, jessie.Namespaces)
		assert.Len(t, jessie.Features, 117)
	} else {
		assert.Fail(t, "jessie is not stored")
		return
	}
}

func getFeatures(a database.Ancestry) []database.AncestryFeature {
	features := []database.AncestryFeature{}
	for _, l := range a.Layers {
		features = append(features, l.Features...)
	}

	return features
}

func TestComputeAncestryFeatures(t *testing.T) {
	vf1 := "format 1"
	vf2 := "format 2"

	nd1 := database.NewNamespaceDetector("apk", "1.0")
	fd1 := database.NewFeatureDetector("fd1", "1.0")
	// this detector only scans one layer with one extra feature, this one
	// should be omitted.
	fd2 := database.NewFeatureDetector("fd2", "1.0")

	ns1a := database.LayerNamespace{
		database.Namespace{
			Name:          "namespace 1:a",
			VersionFormat: vf1,
		}, nd1,
	}

	ns1b := database.LayerNamespace{
		database.Namespace{
			Name:          "namespace 1:b",
			VersionFormat: vf1,
		}, nd1}

	ns2a := database.LayerNamespace{
		database.Namespace{
			Name:          "namespace 2:a",
			VersionFormat: vf2,
		}, nd1}

	ns2b := database.LayerNamespace{
		database.Namespace{
			Name:          "namespace 2:b",
			VersionFormat: vf2,
		}, nd1}

	f1 := database.LayerFeature{
		database.Feature{
			Name:          "feature 1",
			Version:       "0.1",
			VersionFormat: vf1,
		}, fd1}

	f2 := database.LayerFeature{database.Feature{
		Name:          "feature 2",
		Version:       "0.2",
		VersionFormat: vf1,
	}, fd2}

	f3 := database.LayerFeature{
		database.Feature{
			Name:          "feature 1",
			Version:       "0.3",
			VersionFormat: vf2,
		}, fd1}

	f4 := database.LayerFeature{
		database.Feature{
			Name:          "feature 2",
			Version:       "0.3",
			VersionFormat: vf2,
		}, fd1}

	f5 := database.LayerFeature{
		database.Feature{
			Name:          "feature 3",
			Version:       "0.3",
			VersionFormat: vf2,
		},
		fd2,
	}

	// Suppose Clair is watching two files for namespaces one containing ns1
	// changes e.g. os-release and the other one containing ns2 changes e.g.
	// node.
	blank := database.Layer{
		Hash: "blank",
		By:   []database.Detector{nd1, fd1, fd1},
	}
	initNS1a := database.Layer{
		Hash:       "initNS1a",
		By:         []database.Detector{nd1, fd1, fd1},
		Namespaces: []database.LayerNamespace{ns1a},
		Features:   []database.LayerFeature{f1, f2},
	}

	upgradeNS2b := database.Layer{
		Hash:       "upgradeNS2b",
		By:         []database.Detector{nd1, fd1, fd1},
		Namespaces: []database.LayerNamespace{ns2b},
	}

	upgradeNS1b := database.Layer{
		Hash:       "upgradeNS1b",
		By:         []database.Detector{nd1, fd1, fd1, fd2},
		Namespaces: []database.LayerNamespace{ns1b},
		Features:   []database.LayerFeature{f1, f2, f5},
	}

	initNS2a := database.Layer{
		Hash:       "initNS2a",
		By:         []database.Detector{nd1, fd1, fd1},
		Namespaces: []database.LayerNamespace{ns2a},
		Features:   []database.LayerFeature{f3, f4},
	}

	removeF2 := database.Layer{
		Hash:     "removeF2",
		By:       []database.Detector{nd1, fd1, fd1},
		Features: []database.LayerFeature{f1},
	}

	// blank -> ns1:a, f1 f2 (init)
	// -> f1 (feature change)
	// -> ns2:a, f3, f4 (init ns2a)
	// -> ns2:b (ns2 upgrade without changing features)
	// -> blank (empty)
	// -> ns1:b, f1 f2 (ns1 upgrade and add f2)
	// -> f1 (remove f2)
	// -> blank (empty)

	layers := []database.Layer{
		blank,       // empty
		initNS1a,    // namespace: NS1a, features: f1, f2
		removeF2,    // namespace:     , features: f1
		initNS2a,    // namespace: NS2a, features: f3, f4 ( under NS2a )
		upgradeNS2b, // namespace: NS2b, ( f3, f4 are now under NS2b )
		blank,       // empty
		upgradeNS1b, // namespace: NS1b, ( f1, f2 are now under NS1b, and they are introduced in this layer. )
		removeF2,    // namespace:     , features: f1
		blank,
	}

	expected := []database.AncestryLayer{
		{
			"blank",
			[]database.AncestryFeature{},
		},
		{
			"initNS1a",
			[]database.AncestryFeature{{database.NamespacedFeature{f1.Feature, ns1a.Namespace}, f1.By, ns1a.By}},
		},
		{
			"removeF2",
			[]database.AncestryFeature{},
		},
		{
			"initNS2a",
			[]database.AncestryFeature{
				{database.NamespacedFeature{f3.Feature, ns2a.Namespace}, f3.By, ns2a.By},
				{database.NamespacedFeature{f4.Feature, ns2a.Namespace}, f4.By, ns2a.By},
			},
		},
		{
			"upgradeNS2b",
			[]database.AncestryFeature{},
		},
		{
			"blank",
			[]database.AncestryFeature{},
		},
		{
			"upgradeNS1b",
			[]database.AncestryFeature{},
		},
		{
			"removeF2",
			[]database.AncestryFeature{},
		},
		{
			"blank",
			[]database.AncestryFeature{},
		},
	}

	expectedDetectors := []database.Detector{nd1, fd1}
	ancestryLayers, detectors, err := computeAncestryLayers(layers)
	require.Nil(t, err)

	database.AssertDetectorsEqual(t, expectedDetectors, detectors)
	for i := range expected {
		database.AssertAncestryLayerEqual(t, &expected[i], &ancestryLayers[i])
	}
}
