// Copyright 2019 clair authors
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

package ancestry

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/database/pgsql/testutil"
)

var upsertAncestryTests = []struct {
	in    *database.Ancestry
	err   string
	title string
}{
	{
		title: "ancestry with invalid layer",
		in: &database.Ancestry{
			Name: "a1",
			Layers: []database.AncestryLayer{
				{
					Hash: "layer-non-existing",
				},
			},
		},
		err: database.ErrMissingEntities.Error(),
	},
	{
		title: "ancestry with invalid name",
		in:    &database.Ancestry{},
		err:   database.ErrInvalidParameters.Error(),
	},
	{
		title: "new valid ancestry",
		in: &database.Ancestry{
			Name:   "a",
			Layers: []database.AncestryLayer{{Hash: "layer-0"}},
		},
	},
	{
		title: "ancestry with invalid feature",
		in: &database.Ancestry{
			Name: "a",
			By:   []database.Detector{testutil.RealDetectors[1], testutil.RealDetectors[2]},
			Layers: []database.AncestryLayer{{Hash: "layer-1", Features: []database.AncestryFeature{
				{testutil.FakeNamespacedFeatures[1], testutil.FakeDetector[1], testutil.FakeDetector[2]},
			}}},
		},
		err: database.ErrMissingEntities.Error(),
	},
	{
		title: "replace old ancestry",
		in: &database.Ancestry{
			Name: "a",
			By:   []database.Detector{testutil.RealDetectors[1], testutil.RealDetectors[2]},
			Layers: []database.AncestryLayer{
				{"layer-1", []database.AncestryFeature{{testutil.RealNamespacedFeatures[1], testutil.RealDetectors[2], testutil.RealDetectors[1]}}},
			},
		},
	},
}

func TestUpsertAncestry(t *testing.T) {
	tx, cleanup := testutil.CreateTestTxWithFixtures(t, "TestUpsertAncestry")
	defer cleanup()

	for _, test := range upsertAncestryTests {
		t.Run(test.title, func(t *testing.T) {
			err := UpsertAncestry(tx, *test.in)
			if test.err != "" {
				assert.EqualError(t, err, test.err, "unexpected error")
				return
			}
			assert.Nil(t, err)
			actual, ok, err := FindAncestry(tx, test.in.Name)
			assert.Nil(t, err)
			assert.True(t, ok)
			database.AssertAncestryEqual(t, test.in, &actual)
		})
	}
}

var findAncestryTests = []struct {
	title string
	in    string

	ancestry *database.Ancestry
	err      string
	ok       bool
}{
	{
		title:    "missing ancestry",
		in:       "ancestry-non",
		err:      "",
		ancestry: nil,
		ok:       false,
	},
	{
		title:    "valid ancestry",
		in:       "ancestry-2",
		err:      "",
		ok:       true,
		ancestry: testutil.TakeAncestryPointerFromMap(testutil.RealAncestries, 2),
	},
}

func TestFindAncestry(t *testing.T) {
	tx, cleanup := testutil.CreateTestTxWithFixtures(t, "TestFindAncestry")
	defer cleanup()

	for _, test := range findAncestryTests {
		t.Run(test.title, func(t *testing.T) {
			ancestry, ok, err := FindAncestry(tx, test.in)
			if test.err != "" {
				assert.EqualError(t, err, test.err, "unexpected error")
				return
			}

			assert.Nil(t, err)
			assert.Equal(t, test.ok, ok)
			if test.ok {
				database.AssertAncestryEqual(t, test.ancestry, &ancestry)
			}
		})
	}
}
