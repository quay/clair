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
	a1 := database.Ancestry{
		Name: "a1",
		Layers: []database.Layer{
			{Hash: "layer-N"},
		},
	}

	a2 := database.Ancestry{}

	a3 := database.Ancestry{
		Name: "a",
		Layers: []database.Layer{
			{Hash: "layer-0"},
		},
	}

	a4 := database.Ancestry{
		Name: "a",
		Layers: []database.Layer{
			{Hash: "layer-1"},
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

	// invalid case
	assert.NotNil(t, tx.UpsertAncestry(a1, nil, database.Processors{}))
	assert.NotNil(t, tx.UpsertAncestry(a2, nil, database.Processors{}))
	// valid case
	assert.Nil(t, tx.UpsertAncestry(a3, nil, database.Processors{}))
	// replace invalid case
	assert.NotNil(t, tx.UpsertAncestry(a4, []database.NamespacedFeature{nsf1, nsf2}, p))
	// replace valid case
	assert.Nil(t, tx.UpsertAncestry(a4, []database.NamespacedFeature{nsf1}, p))
	// validate
	ancestry, ok, err := tx.FindAncestryFeatures("a")
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

	// not found
	_, _, ok, err := tx.FindAncestry("ancestry-non")
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
	}

	expectedProcessors := database.Processors{
		Detectors: []string{"os-release"},
		Listers:   []string{"dpkg"},
	}

	// found
	a, p, ok2, err := tx.FindAncestry("ancestry-1")
	if assert.Nil(t, err) && assert.True(t, ok2) {
		assertAncestryEqual(t, expected, a)
		assertProcessorsEqual(t, expectedProcessors, p)
	}
}

func assertAncestryWithFeatureEqual(t *testing.T, expected database.AncestryWithFeatures, actual database.AncestryWithFeatures) bool {
	return assertAncestryEqual(t, expected.Ancestry, actual.Ancestry) &&
		assertNamespacedFeatureEqual(t, expected.Features, actual.Features) &&
		assertProcessorsEqual(t, expected.ProcessedBy, actual.ProcessedBy)
}
func assertAncestryEqual(t *testing.T, expected database.Ancestry, actual database.Ancestry) bool {
	return assert.Equal(t, expected.Name, actual.Name) && assert.Equal(t, expected.Layers, actual.Layers)
}

func TestFindAncestryFeatures(t *testing.T) {
	store, tx := openSessionForTest(t, "FindAncestryFeatures", true)
	defer closeTest(t, store, tx)

	// invalid
	_, ok, err := tx.FindAncestryFeatures("ancestry-non")
	if assert.Nil(t, err) {
		assert.False(t, ok)
	}

	expected := database.AncestryWithFeatures{
		Ancestry: database.Ancestry{
			Name: "ancestry-2",
			Layers: []database.Layer{
				{Hash: "layer-0"},
				{Hash: "layer-1"},
				{Hash: "layer-2"},
				{Hash: "layer-3b"},
			},
		},
		ProcessedBy: database.Processors{
			Detectors: []string{"os-release"},
			Listers:   []string{"dpkg"},
		},
		Features: []database.NamespacedFeature{
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
	}
	// valid
	ancestry, ok, err := tx.FindAncestryFeatures("ancestry-2")
	if assert.Nil(t, err) && assert.True(t, ok) {
		assertAncestryEqual(t, expected.Ancestry, ancestry.Ancestry)
		assertNamespacedFeatureEqual(t, expected.Features, ancestry.Features)
		assertProcessorsEqual(t, expected.ProcessedBy, ancestry.ProcessedBy)
	}
}
