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

package pgsql

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/coreos/clair/database"
	cerrors "github.com/coreos/clair/utils/errors"
	"github.com/coreos/clair/utils/types"
)

func TestFindLayer(t *testing.T) {
	datastore, err := openDatabaseForTest("FindLayer", true)
	if err != nil {
		t.Error(err)
		return
	}
	defer datastore.Close()

	// Layer-0: no parent, no namespace, no feature, no vulnerability
	layer, err := datastore.FindLayer("layer-0", false, false)
	if assert.Nil(t, err) && assert.NotNil(t, layer) {
		assert.Equal(t, "layer-0", layer.Name)
		assert.Nil(t, layer.Namespace)
		assert.Nil(t, layer.Parent)
		assert.Equal(t, 1, layer.EngineVersion)
		assert.Len(t, layer.Features, 0)
	}

	layer, err = datastore.FindLayer("layer-0", true, false)
	if assert.Nil(t, err) && assert.NotNil(t, layer) {
		assert.Len(t, layer.Features, 0)
	}

	// Layer-1: one parent, adds two features, one vulnerability
	layer, err = datastore.FindLayer("layer-1", false, false)
	if assert.Nil(t, err) && assert.NotNil(t, layer) {
		assert.Equal(t, layer.Name, "layer-1")
		assert.Equal(t, "debian:7", layer.Namespace.Name)
		if assert.NotNil(t, layer.Parent) {
			assert.Equal(t, "layer-0", layer.Parent.Name)
		}
		assert.Equal(t, 1, layer.EngineVersion)
		assert.Len(t, layer.Features, 0)
	}

	layer, err = datastore.FindLayer("layer-1", true, false)
	if assert.Nil(t, err) && assert.NotNil(t, layer) && assert.Len(t, layer.Features, 2) {
		for _, featureVersion := range layer.Features {
			assert.Equal(t, "debian:7", featureVersion.Feature.Namespace.Name)

			switch featureVersion.Feature.Name {
			case "wechat":
				assert.Equal(t, types.NewVersionUnsafe("0.5"), featureVersion.Version)
			case "openssl":
				assert.Equal(t, types.NewVersionUnsafe("1.0"), featureVersion.Version)
			default:
				t.Errorf("unexpected package %s for layer-1", featureVersion.Feature.Name)
			}
		}
	}

	layer, err = datastore.FindLayer("layer-1", true, true)
	if assert.Nil(t, err) && assert.NotNil(t, layer) && assert.Len(t, layer.Features, 2) {
		for _, featureVersion := range layer.Features {
			assert.Equal(t, "debian:7", featureVersion.Feature.Namespace.Name)

			switch featureVersion.Feature.Name {
			case "wechat":
				assert.Equal(t, types.NewVersionUnsafe("0.5"), featureVersion.Version)
			case "openssl":
				assert.Equal(t, types.NewVersionUnsafe("1.0"), featureVersion.Version)

				if assert.Len(t, featureVersion.AffectedBy, 1) {
					assert.Equal(t, "debian:7", featureVersion.AffectedBy[0].Namespace.Name)
					assert.Equal(t, "CVE-OPENSSL-1-DEB7", featureVersion.AffectedBy[0].Name)
					assert.Equal(t, types.High, featureVersion.AffectedBy[0].Severity)
					assert.Equal(t, "A vulnerability affecting OpenSSL < 2.0 on Debian 7.0", featureVersion.AffectedBy[0].Description)
					assert.Equal(t, "http://google.com/#q=CVE-OPENSSL-1-DEB7", featureVersion.AffectedBy[0].Link)
					assert.Equal(t, types.NewVersionUnsafe("2.0"), featureVersion.AffectedBy[0].FixedBy)
				}
			default:
				t.Errorf("unexpected package %s for layer-1", featureVersion.Feature.Name)
			}
		}
	}
}

func TestInsertLayer(t *testing.T) {
	datastore, err := openDatabaseForTest("InsertLayer", false)
	if err != nil {
		t.Error(err)
		return
	}
	defer datastore.Close()

	// Insert invalid layer.
	testInsertLayerInvalid(t, datastore)

	// Insert a layer tree.
	testInsertLayerTree(t, datastore)

	// Update layer.
	testInsertLayerUpdate(t, datastore)

	// Delete layer.
	testInsertLayerDelete(t, datastore)
}

func testInsertLayerInvalid(t *testing.T, datastore database.Datastore) {
	invalidLayers := []database.Layer{
		{},
		{Name: "layer0", Parent: &database.Layer{}},
		{Name: "layer0", Parent: &database.Layer{Name: "UnknownLayer"}},
	}

	for _, invalidLayer := range invalidLayers {
		err := datastore.InsertLayer(invalidLayer)
		assert.Error(t, err)
	}
}

func testInsertLayerTree(t *testing.T, datastore database.Datastore) {
	f1 := database.FeatureVersion{
		Feature: database.Feature{
			Namespace: database.Namespace{Name: "TestInsertLayerNamespace2"},
			Name:      "TestInsertLayerFeature1",
		},
		Version: types.NewVersionUnsafe("1.0"),
	}
	f2 := database.FeatureVersion{
		Feature: database.Feature{
			Namespace: database.Namespace{Name: "TestInsertLayerNamespace2"},
			Name:      "TestInsertLayerFeature2",
		},
		Version: types.NewVersionUnsafe("0.34"),
	}
	f3 := database.FeatureVersion{
		Feature: database.Feature{
			Namespace: database.Namespace{Name: "TestInsertLayerNamespace2"},
			Name:      "TestInsertLayerFeature3",
		},
		Version: types.NewVersionUnsafe("0.56"),
	}
	f4 := database.FeatureVersion{
		Feature: database.Feature{
			Namespace: database.Namespace{Name: "TestInsertLayerNamespace3"},
			Name:      "TestInsertLayerFeature2",
		},
		Version: types.NewVersionUnsafe("0.34"),
	}
	f5 := database.FeatureVersion{
		Feature: database.Feature{
			Namespace: database.Namespace{Name: "TestInsertLayerNamespace3"},
			Name:      "TestInsertLayerFeature3",
		},
		Version: types.NewVersionUnsafe("0.56"),
	}
	f6 := database.FeatureVersion{
		Feature: database.Feature{
			Namespace: database.Namespace{Name: "TestInsertLayerNamespace3"},
			Name:      "TestInsertLayerFeature4",
		},
		Version: types.NewVersionUnsafe("0.666"),
	}

	layers := []database.Layer{
		{
			Name: "TestInsertLayer1",
		},
		{
			Name:      "TestInsertLayer2",
			Parent:    &database.Layer{Name: "TestInsertLayer1"},
			Namespace: &database.Namespace{Name: "TestInsertLayerNamespace1"},
		},
		// This layer changes the namespace and adds Features.
		{
			Name:      "TestInsertLayer3",
			Parent:    &database.Layer{Name: "TestInsertLayer2"},
			Namespace: &database.Namespace{Name: "TestInsertLayerNamespace2"},
			Features:  []database.FeatureVersion{f1, f2, f3},
		},
		// This layer covers the case where the last layer doesn't provide any new Feature.
		{
			Name:     "TestInsertLayer4a",
			Parent:   &database.Layer{Name: "TestInsertLayer3"},
			Features: []database.FeatureVersion{f1, f2, f3},
		},
		// This layer covers the case where the last layer provides Features.
		// It also modifies the Namespace ("upgrade") but keeps some Features not upgraded, their
		// Namespaces should then remain unchanged.
		{
			Name:      "TestInsertLayer4b",
			Parent:    &database.Layer{Name: "TestInsertLayer3"},
			Namespace: &database.Namespace{Name: "TestInsertLayerNamespace3"},
			Features: []database.FeatureVersion{
				// Deletes TestInsertLayerFeature1.
				// Keep TestInsertLayerFeature2 (old Namespace should be kept):
				f4,
				// Upgrades TestInsertLayerFeature3 (with new Namespace):
				f5,
				// Adds TestInsertLayerFeature4:
				f6,
			},
		},
	}

	var err error
	retrievedLayers := make(map[string]database.Layer)
	for _, layer := range layers {
		if layer.Parent != nil {
			// Retrieve from database its parent and assign.
			parent := retrievedLayers[layer.Parent.Name]
			layer.Parent = &parent
		}

		err = datastore.InsertLayer(layer)
		assert.Nil(t, err)

		retrievedLayers[layer.Name], err = datastore.FindLayer(layer.Name, true, false)
		assert.Nil(t, err)
	}

	l4a := retrievedLayers["TestInsertLayer4a"]
	if assert.NotNil(t, l4a.Namespace) {
		assert.Equal(t, "TestInsertLayerNamespace2", l4a.Namespace.Name)
	}
	assert.Len(t, l4a.Features, 3)
	for _, featureVersion := range l4a.Features {
		if cmpFV(featureVersion, f1) && cmpFV(featureVersion, f2) && cmpFV(featureVersion, f3) {
			assert.Error(t, fmt.Errorf("TestInsertLayer4a contains an unexpected package: %#v. Should contain %#v and %#v and %#v.", featureVersion, f1, f2, f3))
		}
	}

	l4b := retrievedLayers["TestInsertLayer4b"]
	if assert.NotNil(t, l4b.Namespace) {
		assert.Equal(t, "TestInsertLayerNamespace3", l4b.Namespace.Name)
	}
	assert.Len(t, l4b.Features, 3)
	for _, featureVersion := range l4b.Features {
		if cmpFV(featureVersion, f2) && cmpFV(featureVersion, f5) && cmpFV(featureVersion, f6) {
			assert.Error(t, fmt.Errorf("TestInsertLayer4a contains an unexpected package: %#v. Should contain %#v and %#v and %#v.", featureVersion, f2, f4, f6))
		}
	}
}

func testInsertLayerUpdate(t *testing.T, datastore database.Datastore) {
	f7 := database.FeatureVersion{
		Feature: database.Feature{
			Namespace: database.Namespace{Name: "TestInsertLayerNamespace3"},
			Name:      "TestInsertLayerFeature7",
		},
		Version: types.NewVersionUnsafe("0.01"),
	}

	l3, _ := datastore.FindLayer("TestInsertLayer3", true, false)
	l3u := database.Layer{
		Name:      l3.Name,
		Parent:    l3.Parent,
		Namespace: &database.Namespace{Name: "TestInsertLayerNamespaceUpdated1"},
		Features:  []database.FeatureVersion{f7},
	}

	l4u := database.Layer{
		Name:          "TestInsertLayer4",
		Parent:        &database.Layer{Name: "TestInsertLayer3"},
		Features:      []database.FeatureVersion{f7},
		EngineVersion: 2,
	}

	// Try to re-insert without increasing the EngineVersion.
	err := datastore.InsertLayer(l3u)
	assert.Nil(t, err)

	l3uf, err := datastore.FindLayer(l3u.Name, true, false)
	if assert.Nil(t, err) {
		assert.Equal(t, l3.Namespace.Name, l3uf.Namespace.Name)
		assert.Equal(t, l3.EngineVersion, l3uf.EngineVersion)
		assert.Len(t, l3uf.Features, len(l3.Features))
	}

	// Update layer l3.
	// Verify that the Namespace, EngineVersion and FeatureVersions got updated.
	l3u.EngineVersion = 2
	err = datastore.InsertLayer(l3u)
	assert.Nil(t, err)

	l3uf, err = datastore.FindLayer(l3u.Name, true, false)
	if assert.Nil(t, err) {
		assert.Equal(t, l3u.Namespace.Name, l3uf.Namespace.Name)
		assert.Equal(t, l3u.EngineVersion, l3uf.EngineVersion)
		if assert.Len(t, l3uf.Features, 1) {
			assert.True(t, cmpFV(l3uf.Features[0], f7), "Updated layer should have %#v but actually have %#v", f7, l3uf.Features[0])
		}
	}

	// Update layer l4.
	// Verify that the Namespace got updated from its new Parent's, and also verify the
	// EnginVersion and FeatureVersions.
	l4u.Parent = &l3uf
	err = datastore.InsertLayer(l4u)
	assert.Nil(t, err)

	l4uf, err := datastore.FindLayer(l3u.Name, true, false)
	if assert.Nil(t, err) {
		assert.Equal(t, l3u.Namespace.Name, l4uf.Namespace.Name)
		assert.Equal(t, l4u.EngineVersion, l4uf.EngineVersion)
		if assert.Len(t, l4uf.Features, 1) {
			assert.True(t, cmpFV(l3uf.Features[0], f7), "Updated layer should have %#v but actually have %#v", f7, l4uf.Features[0])
		}
	}
}

func testInsertLayerDelete(t *testing.T, datastore database.Datastore) {
	err := datastore.DeleteLayer("TestInsertLayerX")
	assert.Equal(t, cerrors.ErrNotFound, err)

	err = datastore.DeleteLayer("TestInsertLayer3")
	assert.Nil(t, err)

	_, err = datastore.FindLayer("TestInsertLayer3", false, false)
	assert.Equal(t, cerrors.ErrNotFound, err)

	_, err = datastore.FindLayer("TestInsertLayer4a", false, false)
	assert.Equal(t, cerrors.ErrNotFound, err)

	_, err = datastore.FindLayer("TestInsertLayer4b", true, false)
	assert.Equal(t, cerrors.ErrNotFound, err)
}

func cmpFV(a, b database.FeatureVersion) bool {
	return a.Feature.Name == b.Feature.Name &&
		a.Feature.Namespace.Name == b.Feature.Namespace.Name &&
		a.Version.String() == b.Version.String()
}
