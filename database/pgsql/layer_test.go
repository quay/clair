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

	l1 := database.Layer{}
	l2 := database.Layer{Hash: "HESOYAM"}

	// invalid
	assert.NotNil(t, tx.PersistLayer(l1))
	// valid
	assert.Nil(t, tx.PersistLayer(l2))
	// duplicated
	assert.Nil(t, tx.PersistLayer(l2))
}

func TestPersistLayerProcessors(t *testing.T) {
	datastore, tx := openSessionForTest(t, "PersistLayerProcessors", true)
	defer closeTest(t, datastore, tx)

	// invalid
	assert.NotNil(t, tx.PersistLayerContent("hash", []database.Namespace{}, []database.Feature{}, database.Processors{}))
	// valid
	assert.Nil(t, tx.PersistLayerContent("layer-4", []database.Namespace{}, []database.Feature{}, database.Processors{Detectors: []string{"new detector!"}}))
}

func TestFindLayer(t *testing.T) {
	datastore, tx := openSessionForTest(t, "FindLayer", true)
	defer closeTest(t, datastore, tx)

	expected := database.Layer{Hash: "layer-4"}
	expectedProcessors := database.Processors{
		Detectors: []string{"os-release", "apt-sources"},
		Listers:   []string{"dpkg", "rpm"},
	}

	// invalid
	_, _, _, err := tx.FindLayer("")
	assert.NotNil(t, err)
	_, _, ok, err := tx.FindLayer("layer-non")
	assert.Nil(t, err)
	assert.False(t, ok)

	// valid
	layer, processors, ok2, err := tx.FindLayer("layer-4")
	if assert.Nil(t, err) && assert.True(t, ok2) {
		assert.Equal(t, expected, layer)
		assertProcessorsEqual(t, expectedProcessors, processors)
	}
}

func TestFindLayerWithContent(t *testing.T) {
	datastore, tx := openSessionForTest(t, "FindLayerWithContent", true)
	defer closeTest(t, datastore, tx)

	_, _, err := tx.FindLayerWithContent("")
	assert.NotNil(t, err)
	_, ok, err := tx.FindLayerWithContent("layer-non")
	assert.Nil(t, err)
	assert.False(t, ok)

	expectedL := database.LayerWithContent{
		Layer: database.Layer{
			Hash: "layer-4",
		},
		Features: []database.Feature{
			{Name: "fake", Version: "2.0", VersionFormat: "rpm"},
			{Name: "openssl", Version: "2.0", VersionFormat: "dpkg"},
		},
		Namespaces: []database.Namespace{
			{Name: "debian:7", VersionFormat: "dpkg"},
			{Name: "fake:1.0", VersionFormat: "rpm"},
		},
		ProcessedBy: database.Processors{
			Detectors: []string{"os-release", "apt-sources"},
			Listers:   []string{"dpkg", "rpm"},
		},
	}

	layer, ok2, err := tx.FindLayerWithContent("layer-4")
	if assert.Nil(t, err) && assert.True(t, ok2) {
		assertLayerWithContentEqual(t, expectedL, layer)
	}
}

func assertLayerWithContentEqual(t *testing.T, expected database.LayerWithContent, actual database.LayerWithContent) bool {
	return assert.Equal(t, expected.Layer, actual.Layer) &&
		assertFeaturesEqual(t, expected.Features, actual.Features) &&
		assertProcessorsEqual(t, expected.ProcessedBy, actual.ProcessedBy) &&
		assertNamespacesEqual(t, expected.Namespaces, actual.Namespaces)
}
