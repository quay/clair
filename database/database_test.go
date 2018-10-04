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

// Package database_test contains white box test cases for database session
// interface.
package database_test

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/deckarep/golang-set"
	"github.com/pborman/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/pkg/pagination"

	// register database implementations
	"github.com/coreos/clair/database/dbtest"
	_ "github.com/coreos/clair/database/pgsql"
)

// testSession is an interface only for testing purpose in order to look into
// the actual database.
type testSession interface {
	TGetAllDetectors() ([]database.Detector, error)
	TGetAllNotifications() ([]database.NotificationHook, error)
	TGetAllNamespaces() ([]database.Namespace, error)
	TGetAllFeatures() ([]database.Feature, error)
	TGetAllNamespacedFeatures() ([]database.NamespacedFeature, error)
	TGetAllVulnerabilitiesWithAffected() ([]database.VulnerabilityWithAffected, []bool, error)
	TGetAllLock() ([]dbtest.Lock, error)
}

const (
	// Skiped tests are because of unimplemented features or unresolved bugs
	// that require deeper investigation.
	SkipInsertingExistingVulnerability = "SkipInsertingExistingVulnerabilityTests"
	SkipDeleteNonExistingVulnerability = "SkipDeleteNonExistingVulnerability"
	SkipRenewUnexpiredLock             = "SkipRenewUnexpiredLock"
)

var (
	testPaginationKey = pagination.Must(pagination.NewKey())
	testConfigs       = map[string]database.RegistrableComponentConfig{
		"pgsql": testPgsqlConfig("example", true, true),
	}
	store database.Datastore
)

func testPgsqlConfig(testName string, loadFixture bool, manageLife bool) database.RegistrableComponentConfig {
	dbName := "test_" + strings.ToLower(testName) + "_" + strings.Replace(uuid.New(), "-", "_", -1)

	var fixturePath string
	if loadFixture {
		_, filename, _, _ := runtime.Caller(0)
		fixturePath = filepath.Join(filepath.Dir(filename)) + "/pgsql/testdata/data.sql"
	}

	source := fmt.Sprintf("postgresql://postgres@127.0.0.1:5432/%s?sslmode=disable", dbName)
	if sourceEnv := os.Getenv("CLAIR_TEST_PGSQL"); sourceEnv != "" {
		source = fmt.Sprintf(sourceEnv, dbName)
	}

	return database.RegistrableComponentConfig{
		Type: "pgsql",
		Options: map[string]interface{}{
			"source":                  source,
			"cachesize":               0,
			"managedatabaselifecycle": manageLife,
			"fixturepath":             fixturePath,
			"paginationkey":           testPaginationKey.String(),
		},
	}
}

func TestMain(m *testing.M) {
	// for each implementation, open the test database.
	for name, cfg := range testConfigs {
		var err error
		// since a singleton of database is used across all the sessions, it's
		// expected that all tests including error tests must success in random
		// orders.
		fmt.Printf("Test Database Connection = '%s'", cfg.Options["source"])
		store, err = database.Open(cfg)
		if err != nil {
			panic(fmt.Sprintf("Failed to initialize testing database for '%s', error='%s'", name, err))
		}
		// validate the store to implement the test interface
		session, err := store.Begin()
		if err != nil {
			store.Close()
			panic(fmt.Sprintf("Failed to open a session, error='%s'", err.Error()))
		}

		_ = session.(testSession)
		session.Rollback()

		m.Run()
		store.Close()
	}
}

// when the skip string is specified, it skips the test.
func shouldSkip(t *testing.T, title string, skip string) {
	if skip != "" {
		t.Logf("'%s' configures test='%s' to be skipped", skip, title)
		t.SkipNow()
	}
}

func TestFindAncestry(t *testing.T) {
	for _, test := range testFindAncestry {
		t.Run(test.title, func(t *testing.T) {
			tx, err := store.Begin()
			require.Nil(t, err)
			defer tx.Rollback()

			ancestry, ok, err := tx.FindAncestry(test.in)
			if test.err != "" {
				assert.EqualError(t, err, test.err, "unexpected error")
				return
			}

			assert.Nil(t, err)
			assert.Equal(t, test.ok, ok)
			if test.ok {
				dbtest.AssertAncestryEqual(t, test.ancestry, &ancestry)
			}
		})
	}
}

func TestUpsertAncestry(t *testing.T) {
	for _, test := range testUpsertAncestry {
		t.Run(test.title, func(t *testing.T) {
			tx, err := store.Begin()
			require.Nil(t, err)
			defer tx.Rollback()

			err = tx.UpsertAncestry(*test.in)
			if test.err != "" {
				assert.EqualError(t, err, test.err, "unexpected error")
				return
			}
			assert.Nil(t, err)
			actual, ok, err := tx.FindAncestry(test.in.Name)
			assert.Nil(t, err)
			assert.True(t, ok)
			dbtest.AssertAncestryEqual(t, test.in, &actual)
		})
	}
}

func TestPersistDetector(t *testing.T) {
	for _, test := range testPersistDetector {
		t.Run(test.title, func(t *testing.T) {
			tx, err := store.Begin()
			require.Nil(t, err)
			defer tx.Rollback()

			err = tx.PersistDetectors(test.in)
			if test.err != "" {
				require.EqualError(t, err, test.err)
				return
			}

			detectors, err := tx.(testSession).TGetAllDetectors()
			require.Nil(t, err)
			detectorSet := mapset.NewSet()
			for _, d := range detectors {
				detectorSet.Add(d)
			}

			for _, d := range test.in {
				assert.True(t, detectorSet.Contains(d), "missing detector: '%s'", d.String())
			}

		})
	}
}

func TestPersistLayer(t *testing.T) {
	for _, test := range testPersistLayer {
		t.Run(test.title, func(t *testing.T) {
			tx, err := store.Begin()
			require.Nil(t, err)
			defer tx.Rollback()

			err = tx.PersistLayer(test.name, test.features, test.namespaces, test.by)
			if test.err != "" {
				assert.EqualError(t, err, test.err, "unexpected error")
				return
			}

			assert.Nil(t, err)
			if test.layer != nil {
				layer, ok, err := tx.FindLayer(test.name)
				assert.Nil(t, err)
				assert.True(t, ok)
				dbtest.AssertLayerEqual(t, test.layer, &layer)
			}
		})
	}
}

func TestFindLayer(t *testing.T) {
	for _, test := range testFindLayer {
		t.Run(test.title, func(t *testing.T) {
			tx, err := store.Begin()
			require.Nil(t, err)
			defer tx.Rollback()

			layer, ok, err := tx.FindLayer(test.in)
			if test.err != "" {
				assert.EqualError(t, err, test.err, "unexpected error")
				return
			}

			assert.Nil(t, err)
			assert.Equal(t, test.ok, ok)
			if test.ok {
				dbtest.AssertLayerEqual(t, test.out, &layer)
			}
		})
	}
}

func TestFindVulnerabilityNotification(t *testing.T) {
	for _, test := range testFindVulnerabilityNotification {
		t.Run(test.title, func(t *testing.T) {
			tx, err := store.Begin()
			require.Nil(t, err)
			defer tx.Rollback()

			notification, ok, err := tx.FindVulnerabilityNotification(test.inName, test.inPageSize, test.inOldPage, test.inNewPage)
			if test.outErr != "" {
				require.EqualError(t, err, test.outErr)
				return
			}

			require.Nil(t, err)
			if !test.outOk {
				require.Equal(t, test.outOk, ok)
				return
			}

			require.True(t, ok)
			dbtest.AssertVulnerabilityNotificationWithVulnerableEqual(t, testPaginationKey, test.outVuln, &notification)
		})
	}
}

func TestInsertVulnerabilityNotifications(t *testing.T) {
	for _, test := range testInsertVulnerabilityNotifications {
		t.Run(test.title, func(t *testing.T) {
			tx, err := store.Begin()
			require.Nil(t, err)
			defer tx.Rollback()

			err = tx.InsertVulnerabilityNotifications(test.in)
			if test.err != "" {
				require.NotNil(t, err)
			}
		})
	}
}

func TestFindNewNotification(t *testing.T) {
	tx, err := store.Begin()
	require.Nil(t, err)
	defer tx.Rollback()

	for i, test := range testFindNewNotification {
		t.Run(test.title, func(t *testing.T) {
			if i != test.order {
				panic(fmt.Sprintf("ordering must be preserved when running this test='%s'", test.title))
			}

			hook, ok, err := tx.FindNewNotification(test.notifiedBefore)
			if test.err != "" {
				require.EqualError(t, err, test.err)
				return
			}

			if !test.found {
				require.Equal(t, test.found, ok)
				return
			}

			require.True(t, ok)
			require.Equal(t, test.outHook, hook)
			if test.delete {
				require.Nil(t, tx.DeleteNotification(hook.Name))
			}
		})
	}
}

func TestMarkNotificationAsRead(t *testing.T) {
	for _, test := range testMarkNotificationAsRead {
		t.Run(test.title, func(t *testing.T) {
			tx, err := store.Begin()
			require.Nil(t, err)

			defer tx.Rollback()

			err = tx.MarkNotificationAsRead(test.name)
			if test.err != "" {
				require.NotNil(t, err) // TODO(sidac): define the interface error.
				return
			}

			require.Nil(t, err)
			hooks, err := tx.(testSession).TGetAllNotifications()
			require.Nil(t, err)
			// ensure that notified notifications are marked.
			for _, h := range hooks {
				if h.Name == test.name {
					require.NotEqual(t, time.Time{}, h.Notified)
				}
			}
		})
	}
}

func TestDeleteNotification(t *testing.T) {
	for _, test := range testDeleteNotification {
		t.Run(test.title, func(t *testing.T) {
			tx, err := store.Begin()
			require.Nil(t, err)

			defer tx.Rollback()

			err = tx.DeleteNotification(test.name)
			if test.err != "" {
				// TODO(sidac): define the interface error behavior
				require.NotNil(t, err)
				return
			}

			require.Nil(t, err)
			// get all notifications to ensure that the one with test.name is
			// removed.
			notifications, err := tx.(testSession).TGetAllNotifications()
			require.Nil(t, err)
			for _, n := range notifications {
				if n.Name == test.name {
					require.NotEqual(t, time.Time{}, n.Deleted)
				}
			}
		})
	}
}

func TestPersistNamespaces(t *testing.T) {
	for _, test := range testPersistNamespaces {
		t.Run(test.title, func(t *testing.T) {
			tx, err := store.Begin()
			require.Nil(t, err)

			defer tx.Rollback()

			err = tx.PersistNamespaces(test.in)
			if test.err != "" {
				require.EqualError(t, err, test.err)
				return
			}

			require.Nil(t, err)
			// ensure all namespaces are stored in the database, and there's no
			// duplication in the database.
			namespaces, err := tx.(testSession).TGetAllNamespaces()
			require.Nil(t, err)
			namespaceSet := mapset.NewSet()
			for _, n := range namespaces {
				require.False(t, namespaceSet.Contains(n))
				namespaceSet.Add(n)
			}

			for _, n := range test.in {
				require.True(t, namespaceSet.Contains(n))
			}
		})
	}
}

func TestInsertVulnerabilities(t *testing.T) {
	for _, test := range testInsertVulnerabilities {
		t.Run(test.title, func(t *testing.T) {
			shouldSkip(t, test.title, test.skip)

			tx, err := store.Begin()
			require.Nil(t, err)
			defer tx.Rollback()

			err = tx.InsertVulnerabilities(test.in)
			if test.err != "" { // TODO(sidac): update the error handling, currently the errors on the interface is not defined.
				require.NotNil(t, err)
				return
			}

			require.Nil(t, err)

			// ensure all inserted vulnerabilities are in the database
			vulnerabilities, _, err := tx.(testSession).TGetAllVulnerabilitiesWithAffected()
			require.Nil(t, err)

			for _, vuln := range test.in {
				// namespace and vulnerability name must be unique
				found := false
				for _, v := range vulnerabilities {
					if v.Name == vuln.Name && v.Namespace == vuln.Namespace {
						// no duplication is allowed!
						require.False(t, found)
						found = true
						// ensure it's actually the same
						require.True(t, dbtest.AssertVulnerabilityWithAffectedEqual(t, vuln, v))
					}
				}

				require.True(t, found)
			}
		})
	}

}

func TestFindVulnerabilities(t *testing.T) {
	for _, test := range testFindVulnerabilities {
		t.Run(test.title, func(t *testing.T) {
			tx, err := store.Begin()
			require.Nil(t, err)
			defer tx.Rollback()

			out, err := tx.FindVulnerabilities(test.in)
			if test.err != "" {
				require.NotNil(t, err)
				return
			}

			require.Nil(t, err)
			// it's expected the ordering must be preserved
			require.Len(t, out, len(test.out))
			for i, v := range test.out {
				if v.Valid {
					require.True(t, dbtest.AssertVulnerabilityWithAffectedEqual(t, v.VulnerabilityWithAffected, out[i].VulnerabilityWithAffected))
				} else {
					require.Equal(t, v.Valid, out[i].Valid, "expect nullable vulnerability with affected to be not valid. ID=%#v", test.in[i])
				}
			}
		})
	}
}

func TestDeleteVulnerabilities(t *testing.T) {
	for _, test := range testDeleteVulnerabilities {
		t.Run(test.title, func(t *testing.T) {
			shouldSkip(t, test.title, test.skip)

			tx, err := store.Begin()
			require.Nil(t, err)
			defer tx.Rollback()

			err = tx.DeleteVulnerabilities(test.in)
			if test.err != "" {
				require.NotNil(t, err)
				return
			}

			require.Nil(t, err)
			// ensure that all deleted vulnerabilities are removed, but the ones
			// should not be removed are not.
			postVulns, postDeleted, err := tx.(testSession).TGetAllVulnerabilitiesWithAffected()
			for _, v := range test.in {
				for i, pv := range postVulns {
					if pv.Name == v.Name && pv.Namespace.Name == v.Namespace {
						require.True(t, postDeleted[i])
					}
				}
			}
		})
	}
}

func TestLock(t *testing.T) {
	for _, test := range testLock {
		t.Run(test.title, func(t *testing.T) {
			shouldSkip(t, test.title, test.skip)

			tx, err := store.Begin()
			require.Nil(t, err)
			defer tx.Rollback()

			success, expiration, err := tx.Lock(test.name, test.owner, test.duration, test.renew)
			if test.err != "" {
				require.NotNil(t, err)
				return
			}

			require.Nil(t, err)
			require.Equal(t, test.success, success)
			if !test.success {
				return
			}

			// must be in a range, here I set must be within a minute
			assert.True(t,
				expiration.After(test.expiration) &&
					expiration.Before(test.expiration.Add(time.Minute)),
				"Expect (%s) <= expiration(%s) <= (%s)",
				test.expiration,
				expiration,
				test.expiration.Add(time.Minute),
			)
			// exam all locks to ensure the behavior
			locks, err := tx.(testSession).TGetAllLock()
			require.Nil(t, err)

			found := false
			for _, l := range locks {
				if l.Name == test.name {
					require.False(t, found, "duplicated lock")
					require.Equal(t, test.owner, l.Owner)
					require.Equal(t, expiration.String(), l.Until.String())
				}
			}
		})
	}
}

func TestFindKeyValue(t *testing.T) {
	for _, test := range testFindKeyValue {
		t.Run(test.title, func(t *testing.T) {
			tx, err := store.Begin()
			require.Nil(t, err)
			defer tx.Rollback()

			v, ok, err := tx.FindKeyValue(test.key)
			if test.err != "" {
				require.NotNil(t, err)
				return
			}

			require.Nil(t, err)
			if !test.ok {
				assert.False(t, ok)
				return
			}

			require.Equal(t, test.ok, ok)
			require.Equal(t, test.value, v)
		})
	}
}

func TestPersistFeatures(t *testing.T) {
	for _, test := range testPersistFeatures {
		t.Run(test.title, func(t *testing.T) {
			tx, err := store.Begin()
			require.Nil(t, err)

			defer tx.Rollback()

			err = tx.PersistFeatures(test.in)
			if test.err != "" {
				require.NotNil(t, err)
				return
			}

			require.Nil(t, err)
			features, err := tx.(testSession).TGetAllFeatures()
			require.Nil(t, err)

			// ensure features are all preserved without duplication
			featureSet := mapset.NewSet()
			for _, f := range features {
				require.False(t, featureSet.Contains(f))
				featureSet.Add(f)
			}

			for _, f := range test.in {
				require.True(t, featureSet.Contains(f))
			}
		})
	}
}

func TestPersistNamespacedFeatures(t *testing.T) {
	for _, test := range testPersistNamespacedFeatures {
		t.Run(test.title, func(t *testing.T) {
			tx, err := store.Begin()
			require.Nil(t, err)

			defer tx.Rollback()

			err = tx.PersistNamespacedFeatures(test.in)
			if test.err != "" {
				require.NotNil(t, err)
				return
			}

			require.Nil(t, err)
			features, err := tx.(testSession).TGetAllNamespacedFeatures()
			require.Nil(t, err)

			// ensure features are all preserved without duplication
			featureSet := mapset.NewSet()
			for _, f := range features {
				require.False(t, featureSet.Contains(f))
				featureSet.Add(f)
			}

			for _, f := range test.in {
				require.True(t, featureSet.Contains(f))
			}
		})
	}
}

func TestFindAffectedNamespacedFeatures(t *testing.T) {
	for _, test := range testFindAffectedNamespacedFeatures {
		t.Run(test.title, func(t *testing.T) {
			tx, err := store.Begin()
			require.Nil(t, err)
			defer tx.Rollback()

			fs, err := tx.FindAffectedNamespacedFeatures(test.in)
			if test.err != "" {
				require.NotNil(t, err)
				return
			}

			require.Nil(t, err)
			require.Len(t, fs, len(test.out))
			for i, f := range test.out {
				if f.Valid {
					require.True(t, fs[i].Valid)
					dbtest.AssertAffectedNamespacedFeature(t, f.AffectedNamespacedFeature, fs[i].AffectedNamespacedFeature)
				} else {
					require.False(t, fs[i].Valid)
				}
			}
		})
	}
}

// sample database objects and tests
var (
	realFeatures = map[int]database.Feature{
		1: {"ourchat", "0.5", "dpkg"},
		2: {"openssl", "1.0", "dpkg"},
		3: {"openssl", "2.0", "dpkg"},
		4: {"fake", "2.0", "rpm"},
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

	realVulnerabilityAffectedFeature = map[int]database.VulnerabilityWithAffected{
		1: {
			Vulnerability: realVulnerability[1],
			Affected: []database.AffectedFeature{
				{realVulnerability[1].Namespace, "openssl", "2.0", "2.0"},
				{realVulnerability[1].Namespace, "libssl", "1.9-abc", "1.9-abc"},
			},
		},
	}

	realNotification = map[int]database.VulnerabilityNotification{
		1: {
			NotificationHook: database.NotificationHook{
				Name:    "test",
				Created: dbtest.MustParseTime("2039-01-02T03:04:05Z"),
			},
			Old: takeVulnerabilityPointerFromMap(realVulnerability, 2),
			New: takeVulnerabilityPointerFromMap(realVulnerability, 1),
		},
	}

	realLock = map[int]dbtest.Lock{
		1: {"name", "owner", time.Now()},
	}

	realKeyValue = map[int]map[string]string{
		1: {"key": "value"},
	}

	realNotificationHook = map[int]database.NotificationHook{
		1: {"test", dbtest.MustParseTime("2039-01-02T03:04:05Z"), time.Time{}, time.Time{}},
		2: {"victory", dbtest.MustParseTime("2039-01-02T03:04:05Z"), dbtest.MustParseTime("2049-01-02T03:04:05Z"), time.Time{}},
		3: {"bomb!", dbtest.MustParseTime("2039-01-02T03:04:05Z"), dbtest.MustParseTime("2059-01-02T03:04:05Z"), dbtest.MustParseTime("2059-01-02T03:04:05Z")},
	}

	fakeFeatures = map[int]database.Feature{
		1: {
			Name:          "ourchat",
			Version:       "0.6",
			VersionFormat: "dpkg",
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

var testPersistLayer = []struct {
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
			{realFeatures[1], realDetectors[1]},
		},
		err: "database: parameters are not valid",
	},
	{
		title: "layer with non-existing feature",
		name:  "random-forest",
		err:   "database: associated immutable entities are missing in the database",
		by:    []database.Detector{realDetectors[2]},
		features: []database.LayerFeature{
			{fakeFeatures[1], realDetectors[2]},
		},
	},
	{
		title: "layer with non-existing namespace",
		name:  "random-forest2",
		err:   "database: associated immutable entities are missing in the database",
		by:    []database.Detector{realDetectors[1]},
		namespaces: []database.LayerNamespace{
			{fakeNamespaces[1], realDetectors[1]},
		},
	},
	{
		title: "layer with non-existing detector",
		name:  "random-forest3",
		err:   "database: associated immutable entities are missing in the database",
		by:    []database.Detector{fakeDetector[1]},
	},
	{
		title: "valid layer",
		name:  "hamsterhouse",
		by:    []database.Detector{realDetectors[1], realDetectors[2]},
		features: []database.LayerFeature{
			{realFeatures[1], realDetectors[2]},
			{realFeatures[2], realDetectors[2]},
		},
		namespaces: []database.LayerNamespace{
			{realNamespaces[1], realDetectors[1]},
		},
		layer: &database.Layer{
			Hash: "hamsterhouse",
			By:   []database.Detector{realDetectors[1], realDetectors[2]},
			Features: []database.LayerFeature{
				{realFeatures[1], realDetectors[2]},
				{realFeatures[2], realDetectors[2]},
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
			{realFeatures[4], realDetectors[3]},
		},
		namespaces: []database.LayerNamespace{
			{realNamespaces[3], realDetectors[4]},
		},
		layer: &database.Layer{
			Hash: "layer-1",
			By:   []database.Detector{realDetectors[1], realDetectors[2], realDetectors[3], realDetectors[4]},
			Features: []database.LayerFeature{
				{realFeatures[1], realDetectors[2]},
				{realFeatures[2], realDetectors[2]},
				{realFeatures[4], realDetectors[3]},
			},
			Namespaces: []database.LayerNamespace{
				{realNamespaces[1], realDetectors[1]},
				{realNamespaces[3], realDetectors[4]},
			},
		},
	},
}

var testFindNewNotification = []struct {
	order int
	title string

	notifiedBefore time.Time

	outHook database.NotificationHook
	found   bool
	err     string
	delete  bool
}{
	{
		order:          0, // the orders matters for this test
		title:          "0: find ones never notified",
		notifiedBefore: dbtest.MustParseTime("2009-01-02T03:04:05Z"),

		outHook: realNotificationHook[1],
		found:   true,
		delete:  true,
	},
	{
		order: 1,
		title: "1: no notification before this time",

		notifiedBefore: dbtest.MustParseTime("2009-01-02T03:04:05Z"),
	},
	{
		order: 2,
		title: "2: find ones notified before this time",

		notifiedBefore: dbtest.MustParseTime("2050-01-02T03:04:05Z"),

		outHook: realNotificationHook[2],
		found:   true,
		delete:  true,
	},
	{
		order: 3,
		title: "3: no deleted notification",

		notifiedBefore: dbtest.MustParseTime("2060-01-02T03:04:05Z"),
	},
}

var testFindLayer = []struct {
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

var testDeleteNotification = []struct {
	title string

	name string

	err string
}{
	{
		"remove non-existing notification",
		"non-existing",
		"TODO",
	},
	{
		"remove existing notification",
		"test",
		"",
	},
	{
		"remove already removed notification",
		"bomb!",
		"TODO",
	},
}

var testMarkNotificationAsRead = []struct {
	title string

	name string

	err string
}{
	{
		"removes non-existing notification",
		"non-existing",
		"TODO",
	},
	{
		"remove valid notification",
		"test",
		"",
	},
	{
		"remove notification already removed",
		"bomb!",
		"",
	},
}

var testInsertVulnerabilityNotifications = []struct {
	title string
	in    []database.VulnerabilityNotification

	err string
}{
	{
		title: "invalid empty notification",
		in:    []database.VulnerabilityNotification{{}},
		err:   "TODO",
	},
	{
		title: "unknown vulnerability",
		in: []database.VulnerabilityNotification{
			{
				NotificationHook: database.NotificationHook{
					Name:    "random name",
					Created: time.Now(),
				},
				Old: nil,
				New: &database.Vulnerability{},
			},
		},
		err: "TODO",
	},
	{
		title: "invalid duplicated notifications",
		in: []database.VulnerabilityNotification{
			{
				NotificationHook: database.NotificationHook{
					Name:    "random name",
					Created: time.Now(),
				},
				Old: nil,
				New: &database.Vulnerability{
					Name: "CVE-OPENSSL-1-DEB7",
					Namespace: database.Namespace{
						Name:          "debian:7",
						VersionFormat: "dpkg",
					},
				},
			},
			{
				NotificationHook: database.NotificationHook{
					Name:    "random name",
					Created: time.Now(),
				},
				Old: nil,
				New: &database.Vulnerability{
					Name: "CVE-OPENSSL-1-DEB7",
					Namespace: database.Namespace{
						Name:          "debian:7",
						VersionFormat: "dpkg",
					},
				},
			},
		},
		err: "TODO",
	},
	{
		title: "valid notification",
		in: []database.VulnerabilityNotification{
			{
				NotificationHook: database.NotificationHook{
					Name:    "random name",
					Created: time.Now(),
				},
				Old: nil,
				New: &database.Vulnerability{
					Name: "CVE-OPENSSL-1-DEB7",
					Namespace: database.Namespace{
						Name:          "debian:7",
						VersionFormat: "dpkg",
					},
				},
			},
		},
	},
}

var testFindVulnerabilityNotification = []struct {
	title string

	inName     string
	inPageSize int
	inOldPage  pagination.Token
	inNewPage  pagination.Token

	outErr  string
	outOk   bool
	outVuln *database.VulnerabilityNotificationWithVulnerable
}{
	{
		title: "find notification with invalid page",

		inName:     "test",
		inPageSize: 1,
		inOldPage:  pagination.FirstPageToken,
		inNewPage:  pagination.Token("random non sense"),

		outErr: pagination.ErrInvalidToken.Error(),
	},
	{
		title: "find non-existing notification",

		inName:     "non-existing",
		inPageSize: 1,
		inOldPage:  pagination.FirstPageToken,
		inNewPage:  pagination.FirstPageToken,

		outOk: false,
	},
	{
		title: "find existing notification first page",

		inName:     "test",
		inPageSize: 1,
		inOldPage:  pagination.FirstPageToken,
		inNewPage:  pagination.FirstPageToken,

		outVuln: &database.VulnerabilityNotificationWithVulnerable{
			NotificationHook: realNotification[1].NotificationHook,
			Old: &database.PagedVulnerableAncestries{
				Vulnerability: realVulnerability[2],
				Limit:         1,
				Affected:      make(map[int]string),
				Current:       dbtest.MustMarshalToken(testPaginationKey, dbtest.MockPage{0}),
				Next:          dbtest.MustMarshalToken(testPaginationKey, dbtest.MockPage{0}),
				End:           true,
			},
			New: &database.PagedVulnerableAncestries{
				Vulnerability: realVulnerability[1],
				Limit:         1,
				Affected:      map[int]string{3: "ancestry-3"},
				Current:       dbtest.MustMarshalToken(testPaginationKey, dbtest.MockPage{0}),
				Next:          dbtest.MustMarshalToken(testPaginationKey, dbtest.MockPage{4}),
				End:           false,
			},
		},

		outOk: true,
	},

	{
		title: "find existing notification of second page of new affected ancestry",

		inName:     "test",
		inPageSize: 1,
		inOldPage:  pagination.FirstPageToken,
		inNewPage:  dbtest.MustMarshalToken(testPaginationKey, dbtest.MockPage{4}),

		outVuln: &database.VulnerabilityNotificationWithVulnerable{
			NotificationHook: realNotification[1].NotificationHook,
			Old: &database.PagedVulnerableAncestries{
				Vulnerability: realVulnerability[2],
				Limit:         1,
				Affected:      make(map[int]string),
				Current:       dbtest.MustMarshalToken(testPaginationKey, dbtest.MockPage{0}),
				Next:          dbtest.MustMarshalToken(testPaginationKey, dbtest.MockPage{0}),
				End:           true,
			},
			New: &database.PagedVulnerableAncestries{
				Vulnerability: realVulnerability[1],
				Limit:         1,
				Affected:      map[int]string{4: "ancestry-4"},
				Current:       dbtest.MustMarshalToken(testPaginationKey, dbtest.MockPage{4}),
				Next:          dbtest.MustMarshalToken(testPaginationKey, dbtest.MockPage{0}),
				End:           true,
			},
		},

		outOk: true,
	},
}

var testFindAncestry = []struct {
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
		ancestry: takeAncestryPointerFromMap(realAncestries, 2),
	},
}

var testUpsertAncestry = []struct {
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
			By:   []database.Detector{realDetectors[1], realDetectors[2]},
			Layers: []database.AncestryLayer{{Hash: "layer-1", Features: []database.AncestryFeature{
				{fakeNamespacedFeatures[1], fakeDetector[1], fakeDetector[2]},
			}}},
		},
		err: database.ErrMissingEntities.Error(),
	},
	{
		title: "replace old ancestry",
		in: &database.Ancestry{
			Name: "a",
			By:   []database.Detector{realDetectors[1], realDetectors[2]},
			Layers: []database.AncestryLayer{
				{"layer-1", []database.AncestryFeature{{realNamespacedFeatures[1], realDetectors[2], realDetectors[1]}}},
			},
		},
	},
}

var testPersistDetector = []struct {
	title string
	in    []database.Detector
	err   string
}{
	{
		title: "invalid detector",
		in: []database.Detector{
			{},
			database.NewFeatureDetector("name", "2.0"),
		},
		err: database.ErrInvalidParameters.Error(),
	},
	{
		title: "invalid detector 2",
		in: []database.Detector{
			database.NewFeatureDetector("name", "2.0"),
			{"name", "1.0", "random not valid dtype"},
		},
		err: database.ErrInvalidParameters.Error(),
	},
	{
		title: "detectors with some different fields",
		in: []database.Detector{
			database.NewFeatureDetector("name", "2.0"),
			database.NewFeatureDetector("name", "1.0"),
			database.NewNamespaceDetector("name", "1.0"),
		},
	},
	{
		title: "duplicated detectors (parameter level)",
		in: []database.Detector{
			database.NewFeatureDetector("name", "1.0"),
			database.NewFeatureDetector("name", "1.0"),
		},
	},
	{
		title: "duplicated detectors (db level)",
		in: []database.Detector{
			database.NewNamespaceDetector("os-release", "1.0"),
			database.NewNamespaceDetector("os-release", "1.0"),
			database.NewFeatureDetector("dpkg", "1.0"),
		},
	},
}

var testPersistFeatures = []struct {
	title string

	in []database.Feature

	err string
}{
	{
		title: "persist 0 feature",
	},
	{
		title: "persist 1 existing feature",
		in:    []database.Feature{realFeatures[1]},
	},
	{
		title: "persist 1 existing feature and 1 non-existing feature",
		in:    []database.Feature{realFeatures[1], fakeFeatures[1]},
	},
	{
		title: "persist 1 non-existing feature",
		in:    []database.Feature{fakeFeatures[1]},
	},
	{
		title: "persist duplicated features",
		in:    []database.Feature{fakeFeatures[1], fakeFeatures[1]},
	},
}

var testPersistNamespacedFeatures = []struct {
	title string

	in []database.NamespacedFeature

	err string
}{
	{
		title: "persist 0 features",
	},
	{
		title: "persist 1 non-existing namespaced feature with non-existing feature",
		in:    []database.NamespacedFeature{{fakeFeatures[1], realNamespaces[1]}},
		err:   database.ErrMissingEntities.Error(),
	},
	{
		title: "persist 1 non-existing namespaced feature with non-existing namespace",
		in:    []database.NamespacedFeature{{realFeatures[1], fakeNamespaces[1]}},
		err:   database.ErrMissingEntities.Error(),
	},
	{
		title: "persist 2 features, only one is valid and existing",
		in: []database.NamespacedFeature{
			{realFeatures[1], realNamespaces[1]},
			{realFeatures[1], fakeNamespaces[1]},
		},
		err: database.ErrMissingEntities.Error(),
	},
	{
		title: "persist 2 features, only one is valid and non-existing",
		in: []database.NamespacedFeature{
			{realFeatures[3], realNamespaces[2]},
			{realFeatures[1], fakeNamespaces[1]},
		},
		err: database.ErrMissingEntities.Error(),
	},
	{
		title: "persist 2 features",
		in: []database.NamespacedFeature{
			{realFeatures[1], realNamespaces[1]},
			{realFeatures[3], realNamespaces[2]},
		},
	},
	{
		title: "persist 2 duplicated features",
		in: []database.NamespacedFeature{
			{realFeatures[3], realNamespaces[2]},
			{realFeatures[3], realNamespaces[2]},
		},
	},
}

var testFindAffectedNamespacedFeatures = []struct {
	title string

	in []database.NamespacedFeature

	out []database.NullableAffectedNamespacedFeature
	err string
}{
	{
		title: "find features",
		in:    []database.NamespacedFeature{realNamespacedFeatures[2]},
		out: []database.NullableAffectedNamespacedFeature{
			{
				Valid: true, AffectedNamespacedFeature: database.AffectedNamespacedFeature{
					NamespacedFeature: realNamespacedFeatures[2],
					AffectedBy: []database.VulnerabilityWithFixedIn{
						{
							Vulnerability:  realVulnerability[1],
							FixedInVersion: "2.0",
						},
					},
				},
			},
		},
	},
}

var testFindVulnerabilities = []struct {
	title string

	in []database.VulnerabilityID

	out []database.NullableVulnerability
	err string
}{
	{
		title: "find 0 vulnerabilities",
	},
	{
		title: "find 1 existing vulnerability in the database",
		in:    []database.VulnerabilityID{{"CVE-OPENSSL-1-DEB7", "debian:7"}},
		out:   []database.NullableVulnerability{{Valid: true, VulnerabilityWithAffected: realVulnerabilityAffectedFeature[1]}},
	},
	{
		title: "find deleted vulnerability in the database",
		in:    []database.VulnerabilityID{{"CVE-DELETED", "debian:7"}},
		out:   []database.NullableVulnerability{{}},
	},
	{
		title: "find 1 existing vulnerability and 1 removed",
		in:    []database.VulnerabilityID{{"CVE-DELETED", "debian:7"}, {"CVE-OPENSSL-1-DEB7", "debian:7"}},
		out:   []database.NullableVulnerability{{}, {Valid: true, VulnerabilityWithAffected: realVulnerabilityAffectedFeature[1]}},
	},
}

var testFindKeyValue = []struct {
	title string

	key string

	value string
	ok    bool
	err   string
}{}

var testDeleteVulnerabilities = []struct {
	title string

	in []database.VulnerabilityID

	err string

	skip string
}{
	{
		title: "remove 0 vulnerabilities",
	},
	{
		title: "remove non existing vulnerability",
		in:    []database.VulnerabilityID{{"CVE-NOPE", "random"}},
		skip:  SkipDeleteNonExistingVulnerability,
	},
	{
		title: "remove one existing vulnerability and one non-existing vulnerability",
		in:    []database.VulnerabilityID{{"random", "random"}, {"CVE-NOPE", "debian:7"}},
		skip:  SkipDeleteNonExistingVulnerability,
	},
	{
		title: "remove two existing vulnerabilities",
		in:    []database.VulnerabilityID{{"CVE-NOPE", "debian:7"}},
	},
}

var testPersistNamespaces = []struct {
	title string

	in []database.Namespace

	err string
}{
	{
		"store 0 namespaces",
		[]database.Namespace{},
		"",
	},
	{
		"store 3 new namespaces with invalid namespace",
		[]database.Namespace{
			{"new:1", "dpkg"},
			{"new:2", "random"},
			{"new:3", ""},
		},
		"Empty namespace name or version format is not allowed",
	},
	{
		"store namespace without name",
		[]database.Namespace{
			{"", "dpkg"},
		},
		"Empty namespace name or version format is not allowed",
	},
	{
		"store namespace without name and namespace",
		[]database.Namespace{{}},
		"Empty namespace name or version format is not allowed",
	},
	{
		"store valid namespaces with all new namespace in the database",
		[]database.Namespace{{"new:1", "dpkg"}, {"new:2", "rpm"}},
		"",
	},
	{
		"store valid namespaces with duplicated namespace",
		[]database.Namespace{{"debian:71", "dpkg"}, {"debian:71", "dpkg"}},
		"",
	},
	{
		"store valid namespaces with namespaces in the database",
		[]database.Namespace{realNamespaces[1], {"debian:71", "dpkg"}},
		"",
	},
}

var testInsertVulnerabilities = []struct {
	title string
	in    []database.VulnerabilityWithAffected
	err   string

	// some tests should be checked in before the fix check in to verify
	// that the fix works. The skip string contains the name of the skip.
	skip string
}{
	{
		title: "store 0 vulnerabilities",
		in:    []database.VulnerabilityWithAffected{},
	},
	{
		title: "store invalid vulnerability without content",
		in: []database.VulnerabilityWithAffected{
			{Vulnerability: database.Vulnerability{}},
		},
		err: "???",
	},
	{
		title: "store invalid vulnerability with non-existing namespace",
		in: []database.VulnerabilityWithAffected{
			{Vulnerability: database.Vulnerability{Name: "CVE-YES-YES-YES", Namespace: fakeNamespaces[1], Severity: database.UnknownSeverity}},
		},
		err: "???",
	},
	{
		title: "store invalid vulnerability with invalid affected feature that has invalid namespace",
		in: []database.VulnerabilityWithAffected{
			{
				Vulnerability: database.Vulnerability{Name: "CVE-A", Namespace: realNamespaces[1], Severity: database.UnknownSeverity},
				Affected:      []database.AffectedFeature{{fakeNamespaces[1], "somefeature", "2.1", "1.0-2.0"}},
			},
		},
		err: "???",
	},
	{
		title: "store invalid duplicated vulnerabilities",
		in: []database.VulnerabilityWithAffected{
			{Vulnerability: database.Vulnerability{Name: "CVE-A", Namespace: realNamespaces[1], Severity: database.UnknownSeverity}},
			{Vulnerability: database.Vulnerability{Name: "CVE-A", Namespace: realNamespaces[1], Severity: database.UnknownSeverity}},
		},
		err: "???",
	},
	{
		title: "store multiple vulnerabilities with one invalid",
		in: []database.VulnerabilityWithAffected{
			{Vulnerability: database.Vulnerability{Name: "CVE-A", Namespace: realNamespaces[1], Severity: database.UnknownSeverity}},
			{Vulnerability: database.Vulnerability{Name: "CVE-A", Namespace: fakeNamespaces[1], Severity: database.UnknownSeverity}},
		},
		err: "???",
	},
	{
		title: "store vulnerabilities existing in the database",
		in: []database.VulnerabilityWithAffected{
			realVulnerabilityAffectedFeature[1],
		},
		err:  "???",
		skip: SkipInsertingExistingVulnerability,
	},
	{
		title: "store same vulnerability but with different affected features",
		in: []database.VulnerabilityWithAffected{
			{Vulnerability: realVulnerability[1], Affected: []database.AffectedFeature{{realVulnerability[1].Namespace, "feature name", "1.0", "2.0"}}},
		},
		err:  "???",
		skip: SkipInsertingExistingVulnerability,
	},
	{
		title: "store new set of vulnerabilities",
		in: []database.VulnerabilityWithAffected{
			{Vulnerability: database.Vulnerability{Name: "CVE-A", Namespace: realNamespaces[1], Severity: database.UnknownSeverity}, Affected: []database.AffectedFeature{{realNamespaces[1], "feature", "1.0", "1.0"}}},
		},
	},
}

var testLock = []struct {
	skip  string
	title string

	name, owner string
	duration    time.Duration
	renew       bool

	success    bool
	expiration time.Time
	err        string
}{
	{"", "create a new lock", "name3", "owner3", time.Hour, false, true, time.Now().Add(time.Hour), ""},
	{"", "create a duplicated lock", "name1", "owner1", time.Hour, false, false, time.Time{}, ""},
	{"", "create a duplicated lock with another owner", "name1", "owner2", time.Hour, false, false, time.Time{}, ""},
	{SkipRenewUnexpiredLock, "renew an unexpired lock", "name1", "owner1", time.Hour, true, true, dbtest.MustParseTime("2039-01-02T03:04:05Z"), ""},
	{"", "renew a unexpired lock with another owner", "name2", "owner1", time.Hour, true, false, time.Time{}, ""},
	{"", "renew an expired lock", "name2", "owner2", time.Hour, true, true, time.Now().Add(time.Hour), ""},
	{"", "renew an expired lock with another owner", "name2", "owner1", time.Hour, true, false, time.Time{}, ""},
}
