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

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/ext/featurefmt"
	"github.com/coreos/clair/ext/featurens"
	"github.com/coreos/clair/ext/versionfmt/dpkg"
	"github.com/coreos/clair/pkg/strutil"

	// Register the required detectors.
	_ "github.com/coreos/clair/ext/featurefmt/dpkg"
	_ "github.com/coreos/clair/ext/featurefmt/rpm"
	_ "github.com/coreos/clair/ext/featurens/aptsources"
	_ "github.com/coreos/clair/ext/featurens/osrelease"
	_ "github.com/coreos/clair/ext/imagefmt/docker"
)

type mockDatastore struct {
	database.MockDatastore

	layers             map[string]database.LayerWithContent
	ancestry           map[string]database.AncestryWithFeatures
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
	layers := map[string]database.LayerWithContent{}
	for k, l := range md.layers {
		features := append([]database.Feature(nil), l.Features...)
		namespaces := append([]database.Namespace(nil), l.Namespaces...)
		listers := append([]string(nil), l.ProcessedBy.Listers...)
		detectors := append([]string(nil), l.ProcessedBy.Detectors...)
		layers[k] = database.LayerWithContent{
			Layer: database.Layer{
				Hash: l.Hash,
			},
			ProcessedBy: database.Processors{
				Listers:   listers,
				Detectors: detectors,
			},
			Features:   features,
			Namespaces: namespaces,
		}
	}

	ancestry := map[string]database.AncestryWithFeatures{}
	for k, a := range md.ancestry {
		nf := append([]database.NamespacedFeature(nil), a.Features...)
		l := append([]database.Layer(nil), a.Layers...)
		listers := append([]string(nil), a.ProcessedBy.Listers...)
		detectors := append([]string(nil), a.ProcessedBy.Detectors...)
		ancestry[k] = database.AncestryWithFeatures{
			Ancestry: database.Ancestry{
				Name:   a.Name,
				Layers: l,
			},
			ProcessedBy: database.Processors{
				Detectors: detectors,
				Listers:   listers,
			},
			Features: nf,
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
		layers:             make(map[string]database.LayerWithContent),
		ancestry:           make(map[string]database.AncestryWithFeatures),
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

		session.FctFindAncestry = func(name string) (database.Ancestry, database.Processors, bool, error) {
			processors := database.Processors{}
			if session.terminated {
				return database.Ancestry{}, processors, false, errSessionDone
			}
			ancestry, ok := session.copy.ancestry[name]
			return ancestry.Ancestry, ancestry.ProcessedBy, ok, nil
		}

		session.FctFindLayer = func(name string) (database.Layer, database.Processors, bool, error) {
			processors := database.Processors{}
			if session.terminated {
				return database.Layer{}, processors, false, errSessionDone
			}
			layer, ok := session.copy.layers[name]
			return layer.Layer, layer.ProcessedBy, ok, nil
		}

		session.FctFindLayerWithContent = func(name string) (database.LayerWithContent, bool, error) {
			if session.terminated {
				return database.LayerWithContent{}, false, errSessionDone
			}
			layer, ok := session.copy.layers[name]
			return layer, ok, nil
		}

		session.FctPersistLayer = func(layer database.Layer) error {
			if session.terminated {
				return errSessionDone
			}
			if _, ok := session.copy.layers[layer.Hash]; !ok {
				session.copy.layers[layer.Hash] = database.LayerWithContent{Layer: layer}
			}
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

		session.FctPersistFeatures = func(fs []database.Feature) error {
			if session.terminated {
				return errSessionDone
			}
			for _, f := range fs {
				key := FeatureKey(&f)
				_, ok := session.copy.features[key]
				if !ok {
					session.copy.features[key] = f
				}
			}
			return nil
		}

		session.FctPersistLayerContent = func(hash string, namespaces []database.Namespace, features []database.Feature, processedBy database.Processors) error {
			if session.terminated {
				return errSessionDone
			}

			// update the layer
			layer, ok := session.copy.layers[hash]
			if !ok {
				return errors.New("layer not found")
			}

			layerFeatures := map[string]database.Feature{}
			layerNamespaces := map[string]database.Namespace{}
			for _, f := range layer.Features {
				layerFeatures[FeatureKey(&f)] = f
			}
			for _, n := range layer.Namespaces {
				layerNamespaces[n.Name] = n
			}

			// ensure that all the namespaces, features are in the database
			for _, ns := range namespaces {
				if _, ok := session.copy.namespaces[ns.Name]; !ok {
					return errors.New("Namespaces should be in the database")
				}
				if _, ok := layerNamespaces[ns.Name]; !ok {
					layer.Namespaces = append(layer.Namespaces, ns)
					layerNamespaces[ns.Name] = ns
				}
			}

			for _, f := range features {
				if _, ok := session.copy.features[FeatureKey(&f)]; !ok {
					return errors.New("Namespaces should be in the database")
				}
				if _, ok := layerFeatures[FeatureKey(&f)]; !ok {
					layer.Features = append(layer.Features, f)
					layerFeatures[FeatureKey(&f)] = f
				}
			}

			layer.ProcessedBy.Detectors = append(layer.ProcessedBy.Detectors, strutil.CompareStringLists(processedBy.Detectors, layer.ProcessedBy.Detectors)...)
			layer.ProcessedBy.Listers = append(layer.ProcessedBy.Listers, strutil.CompareStringLists(processedBy.Listers, layer.ProcessedBy.Listers)...)

			session.copy.layers[hash] = layer
			return nil
		}

		session.FctUpsertAncestry = func(ancestry database.Ancestry, features []database.NamespacedFeature, processors database.Processors) error {
			if session.terminated {
				return errSessionDone
			}

			// ensure features are in the database
			for _, f := range features {
				if _, ok := session.copy.namespacedFeatures[NamespacedFeatureKey(&f)]; !ok {
					return errors.New("namepsaced feature not in db")
				}
			}

			ancestryWFeature := database.AncestryWithFeatures{
				Ancestry:    ancestry,
				Features:    features,
				ProcessedBy: processors,
			}

			session.copy.ancestry[ancestry.Name] = ancestryWFeature
			return nil
		}

		session.FctPersistNamespacedFeatures = func(namespacedFeatures []database.NamespacedFeature) error {
			for i, f := range namespacedFeatures {
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
	Processors = database.Processors{
		Listers:   featurefmt.ListListers(),
		Detectors: featurens.ListDetectors(),
	}
	m.Run()
}

func FeatureKey(f *database.Feature) string {
	return strings.Join([]string{f.Name, f.VersionFormat, f.Version}, "__")
}

func NamespacedFeatureKey(f *database.NamespacedFeature) string {
	return strings.Join([]string{f.Name, f.Namespace.Name}, "__")
}

func TestProcessAncestryWithDistUpgrade(t *testing.T) {
	// Create the list of Features that should not been upgraded from one layer to another.
	nonUpgradedFeatures := []database.Feature{
		{Name: "libtext-wrapi18n-perl", Version: "0.06-7"},
		{Name: "libtext-charwidth-perl", Version: "0.04-7"},
		{Name: "libtext-iconv-perl", Version: "1.7-5"},
		{Name: "mawk", Version: "1.3.3-17"},
		{Name: "insserv", Version: "1.14.0-5"},
		{Name: "db", Version: "5.1.29-5"},
		{Name: "ustr", Version: "1.0.4-3"},
		{Name: "xz-utils", Version: "5.1.1alpha+20120614-2"},
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
	assert.Len(t, datastore.ancestry["Mock"].Features, 74)
	for _, f := range datastore.ancestry["Mock"].Features {
		if _, ok := nonUpgradedMap[f.Feature]; ok {
			assert.Equal(t, "debian:7", f.Namespace.Name)
		} else {
			assert.Equal(t, "debian:8", f.Namespace.Name)
		}
	}

	assert.Equal(t, []database.Layer{
		{Hash: "blank"},
		{Hash: "wheezy"},
		{Hash: "jessie"},
	}, datastore.ancestry["Mock"].Layers)
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

	processedLayers, err := processLayers(datastore, "Docker", layers)
	assert.Nil(t, err)
	assert.Len(t, processedLayers, 3)
	// ensure resubmit won't break the stuff
	processedLayers, err = processLayers(datastore, "Docker", layers)
	assert.Nil(t, err)
	assert.Len(t, processedLayers, 3)
	// Ensure each processed layer is correct
	assert.Len(t, processedLayers[0].Namespaces, 0)
	assert.Len(t, processedLayers[1].Namespaces, 1)
	assert.Len(t, processedLayers[2].Namespaces, 1)
	assert.Len(t, processedLayers[0].Features, 0)
	assert.Len(t, processedLayers[1].Features, 52)
	assert.Len(t, processedLayers[2].Features, 74)

	// Ensure each layer has expected namespaces and features detected
	if blank, ok := datastore.layers["blank"]; ok {
		assert.Equal(t, blank.ProcessedBy.Detectors, Processors.Detectors)
		assert.Equal(t, blank.ProcessedBy.Listers, Processors.Listers)
		assert.Len(t, blank.Namespaces, 0)
		assert.Len(t, blank.Features, 0)
	} else {
		assert.Fail(t, "blank is not stored")
		return
	}

	if wheezy, ok := datastore.layers["wheezy"]; ok {
		assert.Equal(t, wheezy.ProcessedBy.Detectors, Processors.Detectors)
		assert.Equal(t, wheezy.ProcessedBy.Listers, Processors.Listers)
		assert.Equal(t, wheezy.Namespaces, []database.Namespace{{Name: "debian:7", VersionFormat: dpkg.ParserName}})
		assert.Len(t, wheezy.Features, 52)
	} else {
		assert.Fail(t, "wheezy is not stored")
		return
	}

	if jessie, ok := datastore.layers["jessie"]; ok {
		assert.Equal(t, jessie.ProcessedBy.Detectors, Processors.Detectors)
		assert.Equal(t, jessie.ProcessedBy.Listers, Processors.Listers)
		assert.Equal(t, jessie.Namespaces, []database.Namespace{{Name: "debian:8", VersionFormat: dpkg.ParserName}})
		assert.Len(t, jessie.Features, 74)
	} else {
		assert.Fail(t, "jessie is not stored")
		return
	}
}

// TestUpgradeClair checks if a clair is upgraded and certain ancestry's
// features should not change. We assume that Clair should only upgrade
func TestClairUpgrade(t *testing.T) {
	_, f, _, _ := runtime.Caller(0)
	testDataPath := filepath.Join(filepath.Dir(f)) + "/testdata/DistUpgrade/"

	datastore := newMockDatastore()

	// suppose there are two ancestries.
	layers := []LayerRequest{
		{Hash: "blank", Path: testDataPath + "blank.tar.gz"},
		{Hash: "wheezy", Path: testDataPath + "wheezy.tar.gz"},
		{Hash: "jessie", Path: testDataPath + "jessie.tar.gz"},
	}

	layers2 := []LayerRequest{
		{Hash: "blank", Path: testDataPath + "blank.tar.gz"},
		{Hash: "wheezy", Path: testDataPath + "wheezy.tar.gz"},
	}

	// Suppose user scan an ancestry with an old instance of Clair.
	Processors = database.Processors{
		Detectors: []string{"os-release"},
		Listers:   []string{"rpm"},
	}

	assert.Nil(t, ProcessAncestry(datastore, "Docker", "Mock", layers))
	assert.Len(t, datastore.ancestry["Mock"].Features, 0)

	assert.Nil(t, ProcessAncestry(datastore, "Docker", "Mock2", layers2))
	assert.Len(t, datastore.ancestry["Mock2"].Features, 0)

	// Clair is upgraded to use a new namespace detector. The expected
	// behavior is that all layers will be rescanned with "apt-sources" and
	// the ancestry's features are recalculated.
	Processors = database.Processors{
		Detectors: []string{"os-release", "apt-sources"},
		Listers:   []string{"rpm"},
	}

	// Even though Clair processors are upgraded, the ancestry's features should
	// not be upgraded without posting the ancestry to Clair again.
	assert.Nil(t, ProcessAncestry(datastore, "Docker", "Mock", layers))
	assert.Len(t, datastore.ancestry["Mock"].Features, 0)

	// Clair is upgraded to use a new feature lister. The expected behavior is
	// that all layers will be rescanned with "dpkg" and the ancestry's features
	// are invalidated and recalculated.
	Processors = database.Processors{
		Detectors: []string{"os-release", "apt-sources"},
		Listers:   []string{"rpm", "dpkg"},
	}

	assert.Nil(t, ProcessAncestry(datastore, "Docker", "Mock", layers))
	assert.Len(t, datastore.ancestry["Mock"].Features, 74)
	assert.Nil(t, ProcessAncestry(datastore, "Docker", "Mock2", layers2))
	assert.Len(t, datastore.ancestry["Mock2"].Features, 52)

	// check the namespaces are correct
	for _, f := range datastore.ancestry["Mock"].Features {
		if !assert.NotEqual(t, database.Namespace{}, f.Namespace) {
			assert.Fail(t, "Every feature should have a namespace attached")
		}
	}

	for _, f := range datastore.ancestry["Mock2"].Features {
		if !assert.NotEqual(t, database.Namespace{}, f.Namespace) {
			assert.Fail(t, "Every feature should have a namespace attached")
		}
	}
}

// TestMultipleNamespaces tests computing ancestry features
func TestComputeAncestryFeatures(t *testing.T) {
	vf1 := "format 1"
	vf2 := "format 2"

	ns1a := database.Namespace{
		Name:          "namespace 1:a",
		VersionFormat: vf1,
	}

	ns1b := database.Namespace{
		Name:          "namespace 1:b",
		VersionFormat: vf1,
	}

	ns2a := database.Namespace{
		Name:          "namespace 2:a",
		VersionFormat: vf2,
	}

	ns2b := database.Namespace{
		Name:          "namespace 2:b",
		VersionFormat: vf2,
	}

	f1 := database.Feature{
		Name:          "feature 1",
		Version:       "0.1",
		VersionFormat: vf1,
	}

	f2 := database.Feature{
		Name:          "feature 2",
		Version:       "0.2",
		VersionFormat: vf1,
	}

	f3 := database.Feature{
		Name:          "feature 1",
		Version:       "0.3",
		VersionFormat: vf2,
	}

	f4 := database.Feature{
		Name:          "feature 2",
		Version:       "0.3",
		VersionFormat: vf2,
	}

	// Suppose Clair is watching two files for namespaces one containing ns1
	// changes e.g. os-release and the other one containing ns2 changes e.g.
	// node.
	blank := database.LayerWithContent{Layer: database.Layer{Hash: "blank"}}
	initNS1a := database.LayerWithContent{
		Layer:      database.Layer{Hash: "init ns1a"},
		Namespaces: []database.Namespace{ns1a},
		Features:   []database.Feature{f1, f2},
	}

	upgradeNS2b := database.LayerWithContent{
		Layer:      database.Layer{Hash: "upgrade ns2b"},
		Namespaces: []database.Namespace{ns2b},
	}

	upgradeNS1b := database.LayerWithContent{
		Layer:      database.Layer{Hash: "upgrade ns1b"},
		Namespaces: []database.Namespace{ns1b},
		Features:   []database.Feature{f1, f2},
	}

	initNS2a := database.LayerWithContent{
		Layer:      database.Layer{Hash: "init ns2a"},
		Namespaces: []database.Namespace{ns2a},
		Features:   []database.Feature{f3, f4},
	}

	removeF2 := database.LayerWithContent{
		Layer:    database.Layer{Hash: "remove f2"},
		Features: []database.Feature{f1},
	}

	// blank -> ns1:a, f1 f2 (init)
	// -> f1 (feature change)
	// -> ns2:a, f3, f4 (init ns2a)
	// -> ns2:b (ns2 upgrade without changing features)
	// -> blank (empty)
	// -> ns1:b, f1 f2 (ns1 upgrade and add f2)
	// -> f1 (remove f2)
	// -> blank (empty)

	layers := []database.LayerWithContent{
		blank,
		initNS1a,
		removeF2,
		initNS2a,
		upgradeNS2b,
		blank,
		upgradeNS1b,
		removeF2,
		blank,
	}

	expected := map[database.NamespacedFeature]bool{
		{
			Feature:   f1,
			Namespace: ns1a,
		}: false,
		{
			Feature:   f3,
			Namespace: ns2a,
		}: false,
		{
			Feature:   f4,
			Namespace: ns2a,
		}: false,
	}

	features, err := computeAncestryFeatures(layers)
	assert.Nil(t, err)
	for _, f := range features {
		if assert.Contains(t, expected, f) {
			if assert.False(t, expected[f]) {
				expected[f] = true
			}
		}
	}

	for f, visited := range expected {
		assert.True(t, visited, "expected feature is missing : "+f.Namespace.Name+":"+f.Name)
	}
}
