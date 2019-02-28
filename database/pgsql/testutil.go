// Copyright 2018 clair authors
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
	"database/sql"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/remind101/migrate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/database/pgsql/migrations"
	"github.com/coreos/clair/pkg/pagination"
)

// int keys must be the consistent with the database ID.
var (
	realFeatures = map[int]database.Feature{
		1: {"ourchat", "0.5", "dpkg", "source", database.Namespace{}},
		2: {"openssl", "1.0", "dpkg", "source", database.Namespace{}},
		3: {"openssl", "2.0", "dpkg", "source", database.Namespace{}},
		4: {"fake", "2.0", "rpm", "source", database.Namespace{}},
		5: {"mount", "2.31.1-0.4ubuntu3.1", "dpkg", "binary", database.Namespace{}},
	}

	realNamespaces = map[int]database.Namespace{
		1: {"debian:7", "dpkg"},
		2: {"debian:8", "dpkg"},
		3: {"fake:1.0", "rpm"},
	}

	realNamespacedFeatures = map[int]database.NamespacedFeature{
		1: {realFeatures[1], realNamespaces[1]},
		2: {realFeatures[2], realNamespaces[1]},
		3: {realFeatures[2], realNamespaces[2]},
		4: {realFeatures[3], realNamespaces[1]},
	}

	realDetectors = map[int]database.Detector{
		1: database.NewNamespaceDetector("os-release", "1.0"),
		2: database.NewFeatureDetector("dpkg", "1.0"),
		3: database.NewFeatureDetector("rpm", "1.0"),
		4: database.NewNamespaceDetector("apt-sources", "1.0"),
	}

	realLayers = map[int]database.Layer{
		2: {
			Hash: "layer-1",
			By:   []database.Detector{realDetectors[1], realDetectors[2]},
			Features: []database.LayerFeature{
				{realFeatures[1], realDetectors[2]},
				{realFeatures[2], realDetectors[2]},
			},
			Namespaces: []database.LayerNamespace{
				{realNamespaces[1], realDetectors[1]},
			},
		},
		6: {
			Hash: "layer-4",
			By:   []database.Detector{realDetectors[1], realDetectors[2], realDetectors[3], realDetectors[4]},
			Features: []database.LayerFeature{
				{realFeatures[4], realDetectors[3]},
				{realFeatures[3], realDetectors[2]},
			},
			Namespaces: []database.LayerNamespace{
				{realNamespaces[1], realDetectors[1]},
				{realNamespaces[3], realDetectors[4]},
			},
		},
	}

	realAncestries = map[int]database.Ancestry{
		2: {
			Name: "ancestry-2",
			By:   []database.Detector{realDetectors[2], realDetectors[1]},
			Layers: []database.AncestryLayer{
				{
					"layer-0",
					[]database.AncestryFeature{},
				},
				{
					"layer-1",
					[]database.AncestryFeature{},
				},
				{
					"layer-2",
					[]database.AncestryFeature{
						{
							realNamespacedFeatures[1],
							realDetectors[2],
							realDetectors[1],
						},
					},
				},
				{
					"layer-3b",
					[]database.AncestryFeature{
						{
							realNamespacedFeatures[3],
							realDetectors[2],
							realDetectors[1],
						},
					},
				},
			},
		},
	}

	realVulnerability = map[int]database.Vulnerability{
		1: {
			Name:        "CVE-OPENSSL-1-DEB7",
			Namespace:   realNamespaces[1],
			Description: "A vulnerability affecting OpenSSL < 2.0 on Debian 7.0",
			Link:        "http://google.com/#q=CVE-OPENSSL-1-DEB7",
			Severity:    database.HighSeverity,
		},
		2: {
			Name:        "CVE-NOPE",
			Namespace:   realNamespaces[1],
			Description: "A vulnerability affecting nothing",
			Severity:    database.UnknownSeverity,
		},
	}

	realNotification = map[int]database.VulnerabilityNotification{
		1: {
			NotificationHook: database.NotificationHook{
				Name: "test",
			},
			Old: takeVulnerabilityPointerFromMap(realVulnerability, 2),
			New: takeVulnerabilityPointerFromMap(realVulnerability, 1),
		},
	}

	fakeFeatures = map[int]database.Feature{
		1: {
			Name:          "ourchat",
			Version:       "0.6",
			VersionFormat: "dpkg",
			Type:          "source",
		},
	}

	fakeNamespaces = map[int]database.Namespace{
		1: {"green hat", "rpm"},
	}
	fakeNamespacedFeatures = map[int]database.NamespacedFeature{
		1: {
			Feature:   fakeFeatures[0],
			Namespace: realNamespaces[0],
		},
	}

	fakeDetector = map[int]database.Detector{
		1: {
			Name:    "fake",
			Version: "1.0",
			DType:   database.FeatureDetectorType,
		},
		2: {
			Name:    "fake2",
			Version: "2.0",
			DType:   database.NamespaceDetectorType,
		},
	}
)

func takeVulnerabilityPointerFromMap(m map[int]database.Vulnerability, id int) *database.Vulnerability {
	x := m[id]
	return &x
}

func takeAncestryPointerFromMap(m map[int]database.Ancestry, id int) *database.Ancestry {
	x := m[id]
	return &x
}

func takeLayerPointerFromMap(m map[int]database.Layer, id int) *database.Layer {
	x := m[id]
	return &x
}

func listNamespaces(t *testing.T, tx *pgSession) []database.Namespace {
	rows, err := tx.Query("SELECT name, version_format FROM namespace")
	if err != nil {
		t.FailNow()
	}
	defer rows.Close()

	namespaces := []database.Namespace{}
	for rows.Next() {
		var ns database.Namespace
		err := rows.Scan(&ns.Name, &ns.VersionFormat)
		if err != nil {
			t.FailNow()
		}
		namespaces = append(namespaces, ns)
	}

	return namespaces
}

func assertVulnerabilityNotificationWithVulnerableEqual(t *testing.T, key pagination.Key, expected, actual *database.VulnerabilityNotificationWithVulnerable) bool {
	if expected == actual {
		return true
	}

	if expected == nil || actual == nil {
		return assert.Equal(t, expected, actual)
	}

	return assert.Equal(t, expected.NotificationHook, actual.NotificationHook) &&
		AssertPagedVulnerableAncestriesEqual(t, key, expected.Old, actual.Old) &&
		AssertPagedVulnerableAncestriesEqual(t, key, expected.New, actual.New)
}

func AssertPagedVulnerableAncestriesEqual(t *testing.T, key pagination.Key, expected, actual *database.PagedVulnerableAncestries) bool {
	if expected == actual {
		return true
	}

	if expected == nil || actual == nil {
		return assert.Equal(t, expected, actual)
	}

	return database.AssertVulnerabilityEqual(t, &expected.Vulnerability, &actual.Vulnerability) &&
		assert.Equal(t, expected.Limit, actual.Limit) &&
		assert.Equal(t, mustUnmarshalToken(key, expected.Current), mustUnmarshalToken(key, actual.Current)) &&
		assert.Equal(t, mustUnmarshalToken(key, expected.Next), mustUnmarshalToken(key, actual.Next)) &&
		assert.Equal(t, expected.End, actual.End) &&
		database.AssertIntStringMapEqual(t, expected.Affected, actual.Affected)
}

func mustUnmarshalToken(key pagination.Key, token pagination.Token) Page {
	if token == pagination.FirstPageToken {
		return Page{}
	}

	p := Page{}
	if err := key.UnmarshalToken(token, &p); err != nil {
		panic(err)
	}

	return p
}

func mustMarshalToken(key pagination.Key, v interface{}) pagination.Token {
	token, err := key.MarshalToken(v)
	if err != nil {
		panic(err)
	}

	return token
}

var userDBCount = `SELECT count(datname) FROM pg_database WHERE datistemplate = FALSE AND datname != 'postgres';`

func createAndConnectTestDB(t *testing.T, testName string) (*sql.DB, func()) {
	uri := "postgres@127.0.0.1:5432"
	connectionTemplate := "postgresql://%s?sslmode=disable"
	if envURI := os.Getenv("CLAIR_TEST_PGSQL"); envURI != "" {
		uri = envURI
	}

	db, err := sql.Open("postgres", fmt.Sprintf(connectionTemplate, uri))
	if err != nil {
		panic(err)
	}

	testName = strings.ToLower(testName)
	dbName := fmt.Sprintf("test_%s_%s", testName, time.Now().UTC().Format("2006_01_02_15_04_05"))
	t.Logf("creating temporary database name = %s", dbName)
	_, err = db.Exec("CREATE DATABASE " + dbName)
	if err != nil {
		panic(err)
	}

	testDB, err := sql.Open("postgres", fmt.Sprintf(connectionTemplate, uri+"/"+dbName))
	if err != nil {
		panic(err)
	}

	return testDB, func() {
		t.Logf("cleaning up temporary database %s", dbName)
		defer db.Close()
		if err := testDB.Close(); err != nil {
			panic(err)
		}

		if _, err := db.Exec(`DROP DATABASE ` + dbName); err != nil {
			panic(err)
		}

		// ensure the database is cleaned up
		var count int
		if err := db.QueryRow(userDBCount).Scan(&count); err != nil {
			panic(err)
		}
	}
}

func createTestPgSQL(t *testing.T, testName string) (*pgSQL, func()) {
	connection, cleanup := createAndConnectTestDB(t, testName)
	err := migrate.NewPostgresMigrator(connection).Exec(migrate.Up, migrations.Migrations...)
	if err != nil {
		require.Nil(t, err, err.Error())
	}

	return &pgSQL{connection, nil, Config{PaginationKey: pagination.Must(pagination.NewKey()).String()}}, cleanup
}

func createTestPgSQLWithFixtures(t *testing.T, testName string) (*pgSQL, func()) {
	connection, cleanup := createTestPgSQL(t, testName)
	session, err := connection.Begin()
	if err != nil {
		panic(err)
	}

	defer session.Rollback()

	loadFixtures(session.(*pgSession))
	if err = session.Commit(); err != nil {
		panic(err)
	}

	return connection, cleanup
}

func createTestPgSession(t *testing.T, testName string) (*pgSession, func()) {
	connection, cleanup := createTestPgSQL(t, testName)
	session, err := connection.Begin()
	if err != nil {
		panic(err)
	}

	return session.(*pgSession), func() {
		session.Rollback()
		cleanup()
	}
}

func createTestPgSessionWithFixtures(t *testing.T, testName string) (*pgSession, func()) {
	tx, cleanup := createTestPgSession(t, testName)
	defer func() {
		// ensure to cleanup when loadFixtures failed
		if r := recover(); r != nil {
			cleanup()
		}
	}()

	loadFixtures(tx)
	return tx, cleanup
}

func loadFixtures(tx *pgSession) {
	_, filename, _, _ := runtime.Caller(0)
	fixturePath := filepath.Join(filepath.Dir(filename)) + "/testdata/data.sql"
	d, err := ioutil.ReadFile(fixturePath)
	if err != nil {
		panic(err)
	}

	_, err = tx.Exec(string(d))
	if err != nil {
		panic(err)
	}
}

func assertVulnerabilityWithAffectedEqual(t *testing.T, expected database.VulnerabilityWithAffected, actual database.VulnerabilityWithAffected) bool {
	return assert.Equal(t, expected.Vulnerability, actual.Vulnerability) && assertAffectedFeaturesEqual(t, expected.Affected, actual.Affected)
}

func assertAffectedFeaturesEqual(t *testing.T, expected []database.AffectedFeature, actual []database.AffectedFeature) bool {
	if assert.Len(t, actual, len(expected)) {
		has := map[database.AffectedFeature]bool{}
		for _, i := range expected {
			has[i] = false
		}
		for _, i := range actual {
			if visited, ok := has[i]; !ok {
				return false
			} else if visited {
				return false
			}
			has[i] = true
		}
		return true
	}
	return false
}

func genRandomNamespaces(t *testing.T, count int) []database.Namespace {
	r := make([]database.Namespace, count)
	for i := 0; i < count; i++ {
		r[i] = database.Namespace{
			Name:          fmt.Sprint(rand.Int()),
			VersionFormat: "dpkg",
		}
	}
	return r
}
