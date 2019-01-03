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

	"github.com/coreos/clair/database"

	// register dpkg feature lister for testing
	_ "github.com/coreos/clair/ext/featurefmt/dpkg"
)

func TestPersistFeatures(t *testing.T) {
	datastore, tx := openSessionForTest(t, "PersistFeatures", false)
	defer closeTest(t, datastore, tx)

	f1 := database.Feature{}
	f2 := database.Feature{Name: "n", Version: "v", SourceName: "sn", SourceVersion: "sv", VersionFormat: "vf"}

	// empty
	assert.Nil(t, tx.PersistFeatures([]database.Feature{}))
	// invalid
	assert.NotNil(t, tx.PersistFeatures([]database.Feature{f1}))
	// duplicated
	assert.Nil(t, tx.PersistFeatures([]database.Feature{f2, f2}))
	// existing
	assert.Nil(t, tx.PersistFeatures([]database.Feature{f2}))

	fs := listFeatures(t, tx)
	assert.Len(t, fs, 1)
	assert.Equal(t, f2, fs[0])
}

func TestPersistNamespacedFeatures(t *testing.T) {
	datastore, tx := openSessionForTest(t, "PersistNamespacedFeatures", true)
	defer closeTest(t, datastore, tx)

	// existing features
	f1 := database.Feature{
		Name:          "ourchat",
		Version:       "0.5",
		VersionFormat: "dpkg",
	}

	// non-existing features
	f2 := database.Feature{
		Name: "fake!",
	}

	f3 := database.Feature{
		Name:          "openssl",
		Version:       "2.0",
		VersionFormat: "dpkg",
	}

	// exising namespace
	n1 := database.Namespace{
		Name:          "debian:7",
		VersionFormat: "dpkg",
	}

	n3 := database.Namespace{
		Name:          "debian:8",
		VersionFormat: "dpkg",
	}

	// non-existing namespace
	n2 := database.Namespace{
		Name:          "debian:non",
		VersionFormat: "dpkg",
	}

	// existing namespaced feature
	nf1 := database.NamespacedFeature{
		Namespace: n1,
		Feature:   f1,
	}

	// invalid namespaced feature
	nf2 := database.NamespacedFeature{
		Namespace: n2,
		Feature:   f2,
	}

	// new namespaced feature affected by vulnerability
	nf3 := database.NamespacedFeature{
		Namespace: n3,
		Feature:   f3,
	}

	// namespaced features with namespaces or features not in the database will
	// generate error.
	assert.Nil(t, tx.PersistNamespacedFeatures([]database.NamespacedFeature{}))

	assert.NotNil(t, tx.PersistNamespacedFeatures([]database.NamespacedFeature{nf1, nf2}))
	// valid case: insert nf3
	assert.Nil(t, tx.PersistNamespacedFeatures([]database.NamespacedFeature{nf1, nf3}))

	all := listNamespacedFeatures(t, tx)
	assert.Contains(t, all, nf1)
	assert.Contains(t, all, nf3)
}

func TestVulnerableFeature(t *testing.T) {
	datastore, tx := openSessionForTest(t, "VulnerableFeature", true)
	defer closeTest(t, datastore, tx)

	f1 := database.Feature{
		Name:          "openssl",
		Version:       "1.3",
		VersionFormat: "dpkg",
	}

	n1 := database.Namespace{
		Name:          "debian:7",
		VersionFormat: "dpkg",
	}

	nf1 := database.NamespacedFeature{
		Namespace: n1,
		Feature:   f1,
	}
	assert.Nil(t, tx.PersistFeatures([]database.Feature{f1}))
	assert.Nil(t, tx.PersistNamespacedFeatures([]database.NamespacedFeature{nf1}))
	assert.Nil(t, tx.CacheAffectedNamespacedFeatures([]database.NamespacedFeature{nf1}))
	// ensure the namespaced feature is affected correctly
	anf, err := tx.FindAffectedNamespacedFeatures([]database.NamespacedFeature{nf1})
	if assert.Nil(t, err) &&
		assert.Len(t, anf, 1) &&
		assert.True(t, anf[0].Valid) &&
		assert.Len(t, anf[0].AffectedBy, 1) {
		assert.Equal(t, "CVE-OPENSSL-1-DEB7", anf[0].AffectedBy[0].Name)
	}
}

func TestFindAffectedNamespacedFeatures(t *testing.T) {
	datastore, tx := openSessionForTest(t, "FindAffectedNamespacedFeatures", true)
	defer closeTest(t, datastore, tx)
	ns := database.NamespacedFeature{
		Feature: database.Feature{
			Name:          "openssl",
			Version:       "1.0",
			VersionFormat: "dpkg",
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
	rows, err := tx.Query(`SELECT f.name, f.version, f.version_format, n.name, n.version_format
	FROM feature AS f, namespace AS n, namespaced_feature AS nf
	WHERE nf.feature_id = f.id AND nf.namespace_id = n.id`)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	nf := []database.NamespacedFeature{}
	for rows.Next() {
		f := database.NamespacedFeature{}
		err := rows.Scan(&f.Name, &f.Version, &f.VersionFormat, &f.Namespace.Name, &f.Namespace.VersionFormat)
		if err != nil {
			t.Error(err)
			t.FailNow()
		}
		nf = append(nf, f)
	}

	return nf
}

func listFeatures(t *testing.T, tx *pgSession) []database.Feature {
	rows, err := tx.Query("SELECT name, version, version_format FROM feature")
	if err != nil {
		t.FailNow()
	}

	fs := []database.Feature{}
	for rows.Next() {
		f := database.Feature{}
		err := rows.Scan(&f.Name, &f.Version, &f.VersionFormat)
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
