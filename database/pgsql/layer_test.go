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

var persistLayerTests = []struct {
	title      string
	name       string
	by         []database.Detector
	features   []database.LayerFeature
	namespaces []database.LayerNamespace
	layer      *database.Layer
	err        string
}{
	{
		title: "invalid layer name",
		name:  "",
		err:   "expected non-empty layer hash",
	},
	{
		title: "layer with inconsistent feature and detectors",
		name:  "random-forest",
		by:    []database.Detector{realDetectors[2]},
		features: []database.LayerFeature{
			{realFeatures[1], realDetectors[1], database.Namespace{}},
		},
		err: "parameters are not valid",
	},
	{
		title: "layer with non-existing feature",
		name:  "random-forest",
		err:   "associated immutable entities are missing in the database",
		by:    []database.Detector{realDetectors[2]},
		features: []database.LayerFeature{
			{fakeFeatures[1], realDetectors[2], database.Namespace{}},
		},
	},
	{
		title: "layer with non-existing namespace",
		name:  "random-forest2",
		err:   "associated immutable entities are missing in the database",
		by:    []database.Detector{realDetectors[1]},
		namespaces: []database.LayerNamespace{
			{fakeNamespaces[1], realDetectors[1]},
		},
	},
	{
		title: "layer with non-existing detector",
		name:  "random-forest3",
		err:   "associated immutable entities are missing in the database",
		by:    []database.Detector{fakeDetector[1]},
	},
	{
		title: "valid layer",
		name:  "hamsterhouse",
		by:    []database.Detector{realDetectors[1], realDetectors[2]},
		features: []database.LayerFeature{
			{realFeatures[1], realDetectors[2], database.Namespace{}},
			{realFeatures[2], realDetectors[2], database.Namespace{}},
		},
		namespaces: []database.LayerNamespace{
			{realNamespaces[1], realDetectors[1]},
		},
		layer: &database.Layer{
			Hash: "hamsterhouse",
			By:   []database.Detector{realDetectors[1], realDetectors[2]},
			Features: []database.LayerFeature{
				{realFeatures[1], realDetectors[2], database.Namespace{}},
				{realFeatures[2], realDetectors[2], database.Namespace{}},
			},
			Namespaces: []database.LayerNamespace{
				{realNamespaces[1], realDetectors[1]},
			},
		},
	},
	{
		title: "update existing layer",
		name:  "layer-1",
		by:    []database.Detector{realDetectors[3], realDetectors[4]},
		features: []database.LayerFeature{
			{realFeatures[4], realDetectors[3], database.Namespace{}},
		},
		namespaces: []database.LayerNamespace{
			{realNamespaces[3], realDetectors[4]},
		},
		layer: &database.Layer{
			Hash: "layer-1",
			By:   []database.Detector{realDetectors[1], realDetectors[2], realDetectors[3], realDetectors[4]},
			Features: []database.LayerFeature{
				{realFeatures[1], realDetectors[2], database.Namespace{}},
				{realFeatures[2], realDetectors[2], database.Namespace{}},
				{realFeatures[4], realDetectors[3], database.Namespace{}},
			},
			Namespaces: []database.LayerNamespace{
				{realNamespaces[1], realDetectors[1]},
				{realNamespaces[3], realDetectors[4]},
			},
		},
	},
}

func TestPersistLayer(t *testing.T) {
	datastore, tx := openSessionForTest(t, "PersistLayer", true)
	defer closeTest(t, datastore, tx)

	for _, test := range persistLayerTests {
		t.Run(test.title, func(t *testing.T) {
			err := tx.PersistLayer(test.name, test.features, test.namespaces, test.by)
			if test.err != "" {
				assert.EqualError(t, err, test.err, "unexpected error")
				return
			}

			assert.Nil(t, err)
			if test.layer != nil {
				layer, ok, err := tx.FindLayer(test.name)
				assert.Nil(t, err)
				assert.True(t, ok)
				database.AssertLayerEqual(t, test.layer, &layer)
			}
		})
	}
}

var findLayerTests = []struct {
	title string
	in    string

	out *database.Layer
	err string
	ok  bool
}{
	{
		title: "invalid layer name",
		in:    "",
		err:   "non empty layer hash is expected.",
	},
	{
		title: "non-existing layer",
		in:    "layer-non-existing",
		ok:    false,
		out:   nil,
	},
	{
		title: "existing layer",
		in:    "layer-4",
		ok:    true,
		out:   takeLayerPointerFromMap(realLayers, 6),
	},
}

func TestFindLayer(t *testing.T) {
	datastore, tx := openSessionForTest(t, "FindLayer", true)
	defer closeTest(t, datastore, tx)

	for _, test := range findLayerTests {
		t.Run(test.title, func(t *testing.T) {
			layer, ok, err := tx.FindLayer(test.in)
			if test.err != "" {
				assert.EqualError(t, err, test.err, "unexpected error")
				return
			}

			assert.Nil(t, err)
			assert.Equal(t, test.ok, ok)
			if test.ok {
				database.AssertLayerEqual(t, test.out, &layer)
			}
		})
	}
}
