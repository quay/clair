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

package layer

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/database/pgsql/testutil"
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
		by:    []database.Detector{testutil.RealDetectors[2]},
		features: []database.LayerFeature{
			{testutil.RealFeatures[1], testutil.RealDetectors[1], database.Namespace{}},
		},
		err: "parameters are not valid",
	},
	{
		title: "layer with non-existing feature",
		name:  "random-forest",
		err:   "associated immutable entities are missing in the database",
		by:    []database.Detector{testutil.RealDetectors[2]},
		features: []database.LayerFeature{
			{testutil.FakeFeatures[1], testutil.RealDetectors[2], database.Namespace{}},
		},
	},
	{
		title: "layer with non-existing namespace",
		name:  "random-forest2",
		err:   "associated immutable entities are missing in the database",
		by:    []database.Detector{testutil.RealDetectors[1]},
		namespaces: []database.LayerNamespace{
			{testutil.FakeNamespaces[1], testutil.RealDetectors[1]},
		},
	},
	{
		title: "layer with non-existing detector",
		name:  "random-forest3",
		err:   "associated immutable entities are missing in the database",
		by:    []database.Detector{testutil.FakeDetector[1]},
	},
	{

		title: "valid layer",
		name:  "hamsterhouse",
		by:    []database.Detector{testutil.RealDetectors[1], testutil.RealDetectors[2]},
		features: []database.LayerFeature{
			{testutil.RealFeatures[1], testutil.RealDetectors[2], database.Namespace{}},
			{testutil.RealFeatures[2], testutil.RealDetectors[2], database.Namespace{}},
		},
		namespaces: []database.LayerNamespace{
			{testutil.RealNamespaces[1], testutil.RealDetectors[1]},
		},
		layer: &database.Layer{
			Hash: "hamsterhouse",
			By:   []database.Detector{testutil.RealDetectors[1], testutil.RealDetectors[2]},
			Features: []database.LayerFeature{
				{testutil.RealFeatures[1], testutil.RealDetectors[2], database.Namespace{}},
				{testutil.RealFeatures[2], testutil.RealDetectors[2], database.Namespace{}},
			},
			Namespaces: []database.LayerNamespace{
				{testutil.RealNamespaces[1], testutil.RealDetectors[1]},
			},
		},
	},
	{
		title: "update existing layer",
		name:  "layer-1",
		by:    []database.Detector{testutil.RealDetectors[3], testutil.RealDetectors[4]},
		features: []database.LayerFeature{
			{testutil.RealFeatures[4], testutil.RealDetectors[3], database.Namespace{}},
		},
		namespaces: []database.LayerNamespace{
			{testutil.RealNamespaces[3], testutil.RealDetectors[4]},
		},
		layer: &database.Layer{
			Hash: "layer-1",
			By:   []database.Detector{testutil.RealDetectors[1], testutil.RealDetectors[2], testutil.RealDetectors[3], testutil.RealDetectors[4]},
			Features: []database.LayerFeature{
				{testutil.RealFeatures[1], testutil.RealDetectors[2], database.Namespace{}},
				{testutil.RealFeatures[2], testutil.RealDetectors[2], database.Namespace{}},
				{testutil.RealFeatures[4], testutil.RealDetectors[3], database.Namespace{}},
			},
			Namespaces: []database.LayerNamespace{
				{testutil.RealNamespaces[1], testutil.RealDetectors[1]},
				{testutil.RealNamespaces[3], testutil.RealDetectors[4]},
			},
		},
	},

	{
		title: "layer with potential namespace",
		name:  "layer-potential-namespace",
		by:    []database.Detector{testutil.RealDetectors[3]},
		features: []database.LayerFeature{
			{testutil.RealFeatures[4], testutil.RealDetectors[3], testutil.RealNamespaces[4]},
		},
		namespaces: []database.LayerNamespace{
			{testutil.RealNamespaces[3], testutil.RealDetectors[3]},
		},
		layer: &database.Layer{
			Hash: "layer-potential-namespace",
			By:   []database.Detector{testutil.RealDetectors[3]},
			Features: []database.LayerFeature{
				{testutil.RealFeatures[4], testutil.RealDetectors[3], testutil.RealNamespaces[4]},
			},
			Namespaces: []database.LayerNamespace{
				{testutil.RealNamespaces[3], testutil.RealDetectors[3]},
			},
		},
	},
}

func TestPersistLayer(t *testing.T) {
	tx, cleanup := testutil.CreateTestTxWithFixtures(t, "PersistLayer")
	defer cleanup()

	for _, test := range persistLayerTests {
		t.Run(test.title, func(t *testing.T) {
			err := PersistLayer(tx, test.name, test.features, test.namespaces, test.by)
			if test.err != "" {
				assert.EqualError(t, err, test.err, "unexpected error")
				return
			}

			assert.Nil(t, err)
			if test.layer != nil {
				layer, ok, err := FindLayer(tx, test.name)
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
		out:   testutil.TakeLayerPointerFromMap(testutil.RealLayers, 6),
	},
}

func TestFindLayer(t *testing.T) {
	tx, cleanup := testutil.CreateTestTxWithFixtures(t, "FindLayer")
	defer cleanup()

	for _, test := range findLayerTests {
		t.Run(test.title, func(t *testing.T) {
			layer, ok, err := FindLayer(tx, test.in)
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
