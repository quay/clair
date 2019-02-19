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
	"fmt"
	"math/rand"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/pborman/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/ext/versionfmt"
	"github.com/coreos/clair/ext/versionfmt/dpkg"
	"github.com/coreos/clair/pkg/strutil"
)

const (
	numVulnerabilities = 100
	numFeatures        = 100
)

func testGenRandomVulnerabilityAndNamespacedFeature(t *testing.T, store database.Datastore) ([]database.NamespacedFeature, []database.VulnerabilityWithAffected) {
	tx, err := store.Begin()
	if !assert.Nil(t, err) {
		t.FailNow()
	}

	featureName := "TestFeature"
	featureVersionFormat := dpkg.ParserName
	// Insert the namespace on which we'll work.
	namespace := database.Namespace{
		Name:          "TestRaceAffectsFeatureNamespace1",
		VersionFormat: dpkg.ParserName,
	}

	if !assert.Nil(t, tx.PersistNamespaces([]database.Namespace{namespace})) {
		t.FailNow()
	}

	// Initialize random generator and enforce max procs.
	rand.Seed(time.Now().UnixNano())
	runtime.GOMAXPROCS(runtime.NumCPU())

	// Generate Distinct random features
	features := make([]database.Feature, numFeatures)
	nsFeatures := make([]database.NamespacedFeature, numFeatures)
	for i := 0; i < numFeatures; i++ {
		version := rand.Intn(numFeatures)

		features[i] = *database.NewSourcePackage(featureName, strconv.Itoa(version), featureVersionFormat)
		nsFeatures[i] = database.NamespacedFeature{
			Namespace: namespace,
			Feature:   features[i],
		}
	}

	if !assert.Nil(t, tx.PersistFeatures(features)) {
		t.FailNow()
	}

	// Generate vulnerabilities.
	vulnerabilities := []database.VulnerabilityWithAffected{}
	for i := 0; i < numVulnerabilities; i++ {
		// any version less than this is vulnerable
		version := rand.Intn(numFeatures) + 1

		vulnerability := database.VulnerabilityWithAffected{
			Vulnerability: database.Vulnerability{
				Name:      uuid.New(),
				Namespace: namespace,
				Severity:  database.UnknownSeverity,
			},
			Affected: []database.AffectedFeature{
				{
					Namespace:       namespace,
					FeatureName:     featureName,
					FeatureType:     database.SourcePackage,
					AffectedVersion: strconv.Itoa(version),
					FixedInVersion:  strconv.Itoa(version),
				},
			},
		}

		vulnerabilities = append(vulnerabilities, vulnerability)
	}
	tx.Commit()

	return nsFeatures, vulnerabilities
}

func TestConcurrency(t *testing.T) {
	store, err := openDatabaseForTest("Concurrency", false)
	if !assert.Nil(t, err) {
		t.FailNow()
	}
	defer store.Close()
	start := time.Now()
	var wg sync.WaitGroup
	wg.Add(100)
	for i := 0; i < 100; i++ {
		go func() {
			defer wg.Done()
			nsNamespaces := genRandomNamespaces(t, 100)
			tx, err := store.Begin()
			if !assert.Nil(t, err) {
				t.FailNow()
			}
			assert.Nil(t, tx.PersistNamespaces(nsNamespaces))
			tx.Commit()
		}()
	}
	wg.Wait()
	fmt.Println("total", time.Since(start))
}

func TestCaching(t *testing.T) {
	store, err := openDatabaseForTest("Caching", false)
	require.Nil(t, err)
	defer store.Close()

	nsFeatures, vulnerabilities := testGenRandomVulnerabilityAndNamespacedFeature(t, store)
	tx, err := store.Begin()
	require.Nil(t, err)

	require.Nil(t, tx.PersistNamespacedFeatures(nsFeatures))
	require.Nil(t, tx.Commit())

	tx, err = store.Begin()
	require.Nil(t, tx.Commit())

	require.Nil(t, tx.InsertVulnerabilities(vulnerabilities))
	require.Nil(t, tx.Commit())

	tx, err = store.Begin()
	require.Nil(t, err)
	defer tx.Rollback()

	affected, err := tx.FindAffectedNamespacedFeatures(nsFeatures)
	require.Nil(t, err)

	for _, ansf := range affected {
		require.True(t, ansf.Valid)

		expectedAffectedNames := []string{}
		for _, vuln := range vulnerabilities {
			if ok, err := versionfmt.InRange(dpkg.ParserName, ansf.Version, vuln.Affected[0].AffectedVersion); err == nil {
				if ok {
					expectedAffectedNames = append(expectedAffectedNames, vuln.Name)
				}
			}
		}

		actualAffectedNames := []string{}
		for _, s := range ansf.AffectedBy {
			actualAffectedNames = append(actualAffectedNames, s.Name)
		}

		require.Len(t, strutil.Difference(expectedAffectedNames, actualAffectedNames), 0, "\nvulns: %#v\nfeature:%#v\nexpected:%#v\nactual:%#v", vulnerabilities, ansf.NamespacedFeature, expectedAffectedNames, actualAffectedNames)
		require.Len(t, strutil.Difference(actualAffectedNames, expectedAffectedNames), 0)
	}
}
