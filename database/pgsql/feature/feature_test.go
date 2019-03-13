// Copyright 2016 clair authors
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

package feature

import (
	"database/sql"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/database/pgsql/testutil"
)

func TestPersistFeatures(t *testing.T) {
	tx, cleanup := testutil.CreateTestTx(t, "TestPersistFeatures")
	defer cleanup()

	invalid := database.Feature{}
	valid := *database.NewBinaryPackage("mount", "2.31.1-0.4ubuntu3.1", "dpkg")

	// invalid
	require.NotNil(t, PersistFeatures(tx, []database.Feature{invalid}))
	// existing
	require.Nil(t, PersistFeatures(tx, []database.Feature{valid}))
	require.Nil(t, PersistFeatures(tx, []database.Feature{valid}))

	features := selectAllFeatures(t, tx)
	assert.Equal(t, []database.Feature{valid}, features)
}

func TestPersistNamespacedFeatures(t *testing.T) {
	tx, cleanup := testutil.CreateTestTxWithFixtures(t, "TestPersistNamespacedFeatures")
	defer cleanup()

	// existing features
	f1 := database.NewSourcePackage("ourchat", "0.5", "dpkg")
	// non-existing features
	f2 := database.NewSourcePackage("fake!", "", "")
	// exising namespace
	n1 := database.NewNamespace("debian:7", "dpkg")
	// non-existing namespace
	n2 := database.NewNamespace("debian:non", "dpkg")
	// existing namespaced feature
	nf1 := database.NewNamespacedFeature(n1, f1)
	// invalid namespaced feature
	nf2 := database.NewNamespacedFeature(n2, f2)
	// namespaced features with namespaces or features not in the database will
	// generate error.
	assert.Nil(t, PersistNamespacedFeatures(tx, []database.NamespacedFeature{}))
	assert.NotNil(t, PersistNamespacedFeatures(tx, []database.NamespacedFeature{*nf1, *nf2}))
	// valid case: insert nf3
	assert.Nil(t, PersistNamespacedFeatures(tx, []database.NamespacedFeature{*nf1}))

	all := listNamespacedFeatures(t, tx)
	assert.Contains(t, all, *nf1)
}

func listNamespacedFeatures(t *testing.T, tx *sql.Tx) []database.NamespacedFeature {
	types, err := GetFeatureTypeMap(tx)
	if err != nil {
		panic(err)
	}

	rows, err := tx.Query(`SELECT f.name, f.version, f.version_format, f.type, n.name, n.version_format
	FROM feature AS f, namespace AS n, namespaced_feature AS nf
	WHERE nf.feature_id = f.id AND nf.namespace_id = n.id`)
	if err != nil {
		panic(err)
	}

	nf := []database.NamespacedFeature{}
	for rows.Next() {
		f := database.NamespacedFeature{}
		var typeID int
		err := rows.Scan(&f.Name, &f.Version, &f.VersionFormat, &typeID, &f.Namespace.Name, &f.Namespace.VersionFormat)
		if err != nil {
			panic(err)
		}

		f.Type = types.ByID[typeID]
		nf = append(nf, f)
	}

	return nf
}

func selectAllFeatures(t *testing.T, tx *sql.Tx) []database.Feature {
	types, err := GetFeatureTypeMap(tx)
	if err != nil {
		panic(err)
	}

	rows, err := tx.Query("SELECT name, version, version_format, type FROM feature")
	if err != nil {
		t.FailNow()
	}

	fs := []database.Feature{}
	for rows.Next() {
		f := database.Feature{}
		var typeID int
		err := rows.Scan(&f.Name, &f.Version, &f.VersionFormat, &typeID)
		f.Type = types.ByID[typeID]
		if err != nil {
			t.FailNow()
		}
		fs = append(fs, f)
	}
	return fs
}

func TestFindNamespacedFeatureIDs(t *testing.T) {
	tx, cleanup := testutil.CreateTestTxWithFixtures(t, "TestFindNamespacedFeatureIDs")
	defer cleanup()

	features := []database.NamespacedFeature{}
	expectedIDs := []int{}
	for id, feature := range testutil.RealNamespacedFeatures {
		features = append(features, feature)
		expectedIDs = append(expectedIDs, id)
	}

	features = append(features, testutil.RealNamespacedFeatures[1]) // test duplicated
	expectedIDs = append(expectedIDs, 1)

	namespace := testutil.RealNamespaces[1]
	features = append(features, *database.NewNamespacedFeature(&namespace, database.NewBinaryPackage("not-found", "1.0", "dpkg"))) // test not found feature

	ids, err := FindNamespacedFeatureIDs(tx, features)
	require.Nil(t, err)
	require.Len(t, ids, len(expectedIDs)+1)
	for i, id := range ids {
		if i == len(ids)-1 {
			require.False(t, id.Valid)
		} else {
			require.True(t, id.Valid)
			require.Equal(t, expectedIDs[i], int(id.Int64))
		}
	}
}
