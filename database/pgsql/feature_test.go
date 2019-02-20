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

package pgsql

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coreos/clair/database"
)

func TestPersistFeatures(t *testing.T) {
	tx, cleanup := createTestPgSession(t, "TestPersistFeatures")
	defer cleanup()

	invalid := database.Feature{}
	valid := *database.NewBinaryPackage("mount", "2.31.1-0.4ubuntu3.1", "dpkg")

	// invalid
	require.NotNil(t, tx.PersistFeatures([]database.Feature{invalid}))
	// existing
	require.Nil(t, tx.PersistFeatures([]database.Feature{valid}))
	require.Nil(t, tx.PersistFeatures([]database.Feature{valid}))

	features := selectAllFeatures(t, tx)
	assert.Equal(t, []database.Feature{valid}, features)
}

func TestPersistNamespacedFeatures(t *testing.T) {
	tx, cleanup := createTestPgSessionWithFixtures(t, "TestPersistNamespacedFeatures")
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
	assert.Nil(t, tx.PersistNamespacedFeatures([]database.NamespacedFeature{}))
	assert.NotNil(t, tx.PersistNamespacedFeatures([]database.NamespacedFeature{*nf1, *nf2}))
	// valid case: insert nf3
	assert.Nil(t, tx.PersistNamespacedFeatures([]database.NamespacedFeature{*nf1}))

	all := listNamespacedFeatures(t, tx)
	assert.Contains(t, all, *nf1)
}

func TestFindAffectedNamespacedFeatures(t *testing.T) {
	datastore, tx := openSessionForTest(t, "FindAffectedNamespacedFeatures", true)
	defer closeTest(t, datastore, tx)
	ns := database.NamespacedFeature{
		Feature: database.Feature{
			Name:          "openssl",
			Version:       "1.0",
			VersionFormat: "dpkg",
			Type:          database.SourcePackage,
		},
		Namespace: database.Namespace{
			Name:          "debian:7",
			VersionFormat: "dpkg",
		},
	}

	ans, err := tx.FindAffectedNamespacedFeatures([]database.NamespacedFeature{ns})
	if assert.Nil(t, err) &&
		assert.Len(t, ans, 1) &&
		assert.True(t, ans[0].Valid) &&
		assert.Len(t, ans[0].AffectedBy, 1) {
		assert.Equal(t, "CVE-OPENSSL-1-DEB7", ans[0].AffectedBy[0].Name)
	}
}

func listNamespacedFeatures(t *testing.T, tx *pgSession) []database.NamespacedFeature {
	types, err := tx.getFeatureTypeMap()
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

		f.Type = types.byID[typeID]
		nf = append(nf, f)
	}

	return nf
}

func selectAllFeatures(t *testing.T, tx *pgSession) []database.Feature {
	types, err := tx.getFeatureTypeMap()
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
		f.Type = types.byID[typeID]
		if err != nil {
			t.FailNow()
		}
		fs = append(fs, f)
	}
	return fs
}

func assertNamespacedFeatureEqual(t *testing.T, expected []database.NamespacedFeature, actual []database.NamespacedFeature) bool {
	if assert.Len(t, actual, len(expected)) {
		has := map[database.NamespacedFeature]bool{}
		for _, nf := range expected {
			has[nf] = false
		}

		for _, nf := range actual {
			has[nf] = true
		}

		for nf, visited := range has {
			if !assert.True(t, visited, nf.Namespace.Name+":"+nf.Name+" is expected") {
				return false
			}
		}
		return true
	}
	return false
}

func TestFindNamespacedFeatureIDs(t *testing.T) {
	tx, cleanup := createTestPgSessionWithFixtures(t, "TestFindNamespacedFeatureIDs")
	defer cleanup()

	features := []database.NamespacedFeature{}
	expectedIDs := []int{}
	for id, feature := range realNamespacedFeatures {
		features = append(features, feature)
		expectedIDs = append(expectedIDs, id)
	}

	features = append(features, realNamespacedFeatures[1]) // test duplicated
	expectedIDs = append(expectedIDs, 1)

	namespace := realNamespaces[1]
	features = append(features, *database.NewNamespacedFeature(&namespace, database.NewBinaryPackage("not-found", "1.0", "dpkg"))) // test not found feature

	ids, err := tx.findNamespacedFeatureIDs(features)
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
