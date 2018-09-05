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
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/coreos/clair/database"
)

func TestUpsertAncestry(t *testing.T) {
	store, tx := openSessionForTest(t, "UpsertAncestry", true)
	defer closeTest(t, store, tx)
	a1 := database.AncestryWithContent{
		Ancestry: database.Ancestry{
			Name: "a1",
			Layers: []database.Layer{
				{Hash: "layer-N"},
			},
		},
		Layers: []database.AncestryLayer{
			{
				Layer: database.Layer{
					Hash: "layer-N",
				},
			},
		},
	}

	a2 := database.AncestryWithContent{}

	a3 := database.AncestryWithContent{
		Ancestry: database.Ancestry{
			Name: "a",
			Layers: []database.Layer{
				{Hash: "layer-0"},
			},
		},
		Layers: []database.AncestryLayer{
			{
				Layer: database.Layer{
					Hash: "layer-0",
				},
			},
		},
	}

	a4 := database.AncestryWithContent{
		Ancestry: database.Ancestry{
			Name: "a",
			Layers: []database.Layer{
				{Hash: "layer-1"},
			},
		},
		Layers: []database.AncestryLayer{
			{
				Layer: database.Layer{
					Hash: "layer-1",
				},
			},
		},
	}

	f1 := database.Feature{
		Name:          "wechat",
		Version:       "0.5",
		VersionFormat: "dpkg",
	}

	// not in database
	f2 := database.Feature{
		Name:          "wechat",
		Version:       "0.6",
		VersionFormat: "dpkg",
	}

	n1 := database.Namespace{
		Name:          "debian:7",
		VersionFormat: "dpkg",
	}

	p := database.Processors{
		Listers:   []string{"dpkg", "non-existing"},
		Detectors: []string{"os-release", "non-existing"},
	}

	nsf1 := database.NamespacedFeature{
		Namespace: n1,
		Feature:   f1,
	}

	// not in database
	nsf2 := database.NamespacedFeature{
		Namespace: n1,
		Feature:   f2,
	}

	a4.ProcessedBy = p
	// invalid case
	assert.NotNil(t, tx.UpsertAncestry(a1))
	assert.NotNil(t, tx.UpsertAncestry(a2))
	// valid case
	assert.Nil(t, tx.UpsertAncestry(a3))
	a4.Layers[0].DetectedFeatures = []database.NamespacedFeature{nsf1, nsf2}
	// replace invalid case
	assert.NotNil(t, tx.UpsertAncestry(a4))
	a4.Layers[0].DetectedFeatures = []database.NamespacedFeature{nsf1}
	// replace valid case
	assert.Nil(t, tx.UpsertAncestry(a4))
	// validate
	ancestry, ok, err := tx.FindAncestryWithContent("a")
	assert.Nil(t, err)
	assert.True(t, ok)
	assert.Equal(t, a4, ancestry.Ancestry)
}

func assertProcessorsEqual(t *testing.T, expected database.Processors, actual database.Processors) bool {
	sort.Strings(expected.Detectors)
	sort.Strings(actual.Detectors)
	sort.Strings(expected.Listers)
	sort.Strings(actual.Listers)
	return assert.Equal(t, expected.Detectors, actual.Detectors) && assert.Equal(t, expected.Listers, actual.Listers)
}

func TestFindAncestry(t *testing.T) {
	store, tx := openSessionForTest(t, "FindAncestry", true)
	defer closeTest(t, store, tx)

	_, ok, err := tx.FindAncestry("ancestry-non")
	assert.Nil(t, err)
	assert.False(t, ok)

	expected := database.Ancestry{
		Name: "ancestry-1",
		Layers: []database.Layer{
			{Hash: "layer-0"},
			{Hash: "layer-1"},
			{Hash: "layer-2"},
			{Hash: "layer-3a"},
		},
		ProcessedBy: database.Processors{
			Detectors: []string{"os-release"},
			Listers:   []string{"dpkg"},
		},
	}

	a, ok2, err := tx.FindAncestry("ancestry-1")
	if assert.Nil(t, err) && assert.True(t, ok2) {
		assertAncestryEqual(t, expected, a)
	}
}

func assertAncestryWithFeatureEqual(t *testing.T, expected database.AncestryWithContent, actual database.AncestryWithContent) bool {
	if assertAncestryEqual(t, expected.Ancestry, actual.Ancestry) && assert.Equal(t, len(expected.Layers), len(actual.Layers)) {
		for index, layer := range expected.Layers {
			if !assertAncestryLayerEqual(t, layer, actual.Layers[index]) {
				return false
			}
		}
		return true
	}
	return false
}

func assertAncestryLayerEqual(t *testing.T, expected database.AncestryLayer, actual database.AncestryLayer) bool {
	return assertLayerEqual(t, expected.Layer, actual.Layer) &&
		assertNamespacedFeatureEqual(t, expected.DetectedFeatures, actual.DetectedFeatures)
}

func assertAncestryEqual(t *testing.T, expected database.Ancestry, actual database.Ancestry) bool {
	return assert.Equal(t, expected.Name, actual.Name) &&
		assert.Equal(t, expected.Layers, actual.Layers) &&
		assertProcessorsEqual(t, expected.ProcessedBy, actual.ProcessedBy)
}

func TestFindAncestryWithContent(t *testing.T) {
	store, tx := openSessionForTest(t, "FindAncestryWithContent", true)
	defer closeTest(t, store, tx)

	// invalid
	_, ok, err := tx.FindAncestryWithContent("ancestry-non")
	if assert.Nil(t, err) {
		assert.False(t, ok)
	}

	expected := database.AncestryWithContent{
		Ancestry: database.Ancestry{
			Name: "ancestry-2",
			Layers: []database.Layer{
				{Hash: "layer-0"},
				{Hash: "layer-1"},
				{Hash: "layer-2"},
				{Hash: "layer-3b"},
			},
			ProcessedBy: database.Processors{
				Detectors: []string{"os-release"},
				Listers:   []string{"dpkg"},
			},
		},

		Layers: []database.AncestryLayer{
			{
				Layer: database.Layer{
					Hash: "layer-0",
				},
				DetectedFeatures: []database.NamespacedFeature{
					{
						Namespace: database.Namespace{
							Name:          "debian:7",
							VersionFormat: "dpkg",
						},
						Feature: database.Feature{
							Name:          "wechat",
							Version:       "0.5",
							VersionFormat: "dpkg",
						},
					},
					{
						Namespace: database.Namespace{
							Name:          "debian:8",
							VersionFormat: "dpkg",
						},
						Feature: database.Feature{
							Name:          "openssl",
							Version:       "1.0",
							VersionFormat: "dpkg",
						},
					},
				},
			},
			{
				Layer: database.Layer{
					Hash: "layer-1",
				},
			},
			{
				Layer: database.Layer{
					Hash: "layer-2",
				},
			},
			{
				Layer: database.Layer{
					Hash: "layer-3b",
				},
			},
		},
	}
	// valid
	ancestry, ok, err := tx.FindAncestryWithContent("ancestry-2")
	if assert.Nil(t, err) && assert.True(t, ok) {
		assertAncestryWithFeatureEqual(t, expected, ancestry)
	}
}
