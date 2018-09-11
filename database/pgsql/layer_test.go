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

package pgsql

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/coreos/clair/database"
)

func TestPersistLayer(t *testing.T) {
	datastore, tx := openSessionForTest(t, "PersistLayer", false)
	defer closeTest(t, datastore, tx)

	// invalid
	assert.NotNil(t, tx.PersistLayer("", nil, nil, database.Processors{}))
	// insert namespaces + features to
	namespaces := []database.Namespace{
		{
			Name:          "sushi shop",
			VersionFormat: "apk",
		},
	}

	features := []database.Feature{
		{
			Name:          "blue fin sashimi",
			Version:       "v1.0",
			VersionFormat: "apk",
		},
	}

	processors := database.Processors{
		Listers:   []string{"release"},
		Detectors: []string{"apk"},
	}

	assert.Nil(t, tx.PersistNamespaces(namespaces))
	assert.Nil(t, tx.PersistFeatures(features))

	// Valid
	assert.Nil(t, tx.PersistLayer("RANDOM_FOREST", namespaces, features, processors))

	nonExistingFeature := []database.Feature{{Name: "lobster sushi", Version: "v0.1", VersionFormat: "apk"}}
	// Invalid:
	assert.NotNil(t, tx.PersistLayer("RANDOM_FOREST", namespaces, nonExistingFeature, processors))

	assert.Nil(t, tx.PersistFeatures(nonExistingFeature))
	// Update the layer
	assert.Nil(t, tx.PersistLayer("RANDOM_FOREST", namespaces, nonExistingFeature, processors))

	// confirm update
	layer, ok, err := tx.FindLayer("RANDOM_FOREST")
	assert.Nil(t, err)
	assert.True(t, ok)

	expectedLayer := database.Layer{
		LayerMetadata: database.LayerMetadata{
			Hash:        "RANDOM_FOREST",
			ProcessedBy: processors,
		},
		Features:   append(features, nonExistingFeature...),
		Namespaces: namespaces,
	}

	assertLayerWithContentEqual(t, expectedLayer, layer)
}

func TestFindLayer(t *testing.T) {
	datastore, tx := openSessionForTest(t, "FindLayer", true)
	defer closeTest(t, datastore, tx)

	_, _, err := tx.FindLayer("")
	assert.NotNil(t, err)
	_, ok, err := tx.FindLayer("layer-non")
	assert.Nil(t, err)
	assert.False(t, ok)

	expectedL := database.Layer{
		LayerMetadata: database.LayerMetadata{
			Hash: "layer-4",
			ProcessedBy: database.Processors{
				Detectors: []string{"os-release", "apt-sources"},
				Listers:   []string{"dpkg", "rpm"},
			},
		},
		Features: []database.Feature{
			{Name: "fake", Version: "2.0", VersionFormat: "rpm"},
			{Name: "openssl", Version: "2.0", VersionFormat: "dpkg"},
		},
		Namespaces: []database.Namespace{
			{Name: "debian:7", VersionFormat: "dpkg"},
			{Name: "fake:1.0", VersionFormat: "rpm"},
		},
	}

	layer, ok2, err := tx.FindLayer("layer-4")
	if assert.Nil(t, err) && assert.True(t, ok2) {
		assertLayerWithContentEqual(t, expectedL, layer)
	}
}

func assertLayerWithContentEqual(t *testing.T, expected database.Layer, actual database.Layer) bool {
	return assertLayerEqual(t, expected.LayerMetadata, actual.LayerMetadata) &&
		assertFeaturesEqual(t, expected.Features, actual.Features) &&
		assertNamespacesEqual(t, expected.Namespaces, actual.Namespaces)
}

func assertLayerEqual(t *testing.T, expected database.LayerMetadata, actual database.LayerMetadata) bool {
	return assertProcessorsEqual(t, expected.ProcessedBy, actual.ProcessedBy) &&
		assert.Equal(t, expected.Hash, actual.Hash)
}
