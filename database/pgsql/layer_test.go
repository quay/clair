package pgsql

import (
	"fmt"
	"testing"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/utils/types"
	"github.com/stretchr/testify/assert"
)

func TestFindLayer(t *testing.T) {
	datastore, err := OpenForTest("FindLayer", true)
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
	datastore, err := OpenForTest("InsertLayer", true)
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
	// TODO(Quentin-M)

	// Delete layer.
	// TODO(Quentin-M)
}

func testInsertLayerInvalid(t *testing.T, datastore database.Datastore) {
	invalidLayers := []database.Layer{
		database.Layer{},
		database.Layer{Name: "layer0", Parent: &database.Layer{}},
		database.Layer{Name: "layer0", Parent: &database.Layer{Name: "UnknownLayer"}},
	}

	for _, invalidLayer := range invalidLayers {
		err := datastore.InsertLayer(invalidLayer)
		assert.Error(t, err)
	}
}

func testInsertLayerTree(t *testing.T, datastore database.Datastore) {
	fmt.Println("- testInsertLayerTree")

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
		Version: types.NewVersionUnsafe("0.57"),
	}
	f6 := database.FeatureVersion{
		Feature: database.Feature{
			Namespace: database.Namespace{Name: "TestInsertLayerNamespace3"},
			Name:      "TestInsertLayerFeature4",
		},
		Version: types.NewVersionUnsafe("0.666"),
	}

	layers := []database.Layer{
		database.Layer{
			Name: "TestInsertLayer1",
		},
		database.Layer{
			Name:      "TestInsertLayer2",
			Parent:    &database.Layer{Name: "TestInsertLayer1"},
			Namespace: &database.Namespace{Name: "TestInsertLayerNamespace1"},
		},
		// This layer changes the namespace and adds Features.
		database.Layer{
			Name:      "TestInsertLayer3",
			Parent:    &database.Layer{Name: "TestInsertLayer2"},
			Namespace: &database.Namespace{Name: "TestInsertLayerNamespace2"},
			Features:  []database.FeatureVersion{f1, f2, f3},
		},
		// This layer covers the case where the last layer doesn't provide any new Feature.
		database.Layer{
			Name:     "TestInsertLayer4a",
			Parent:   &database.Layer{Name: "TestInsertLayer3"},
			Features: []database.FeatureVersion{f1, f2, f3},
		},
		// This layer covers the case where the last layer provides Features.
		// It also modifies the Namespace ("upgrade") but keeps some Features not upgraded, their
		// Namespaces should then remain unchanged.
		database.Layer{
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

func cmpFV(a, b database.FeatureVersion) bool {
	return a.Feature.Name == b.Feature.Name &&
		a.Feature.Namespace.Name == b.Feature.Namespace.Name &&
		a.Version.String() == b.Version.String()
}
