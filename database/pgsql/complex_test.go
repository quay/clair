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

		features[i] = database.Feature{
			Name:          featureName,
			VersionFormat: featureVersionFormat,
			Version:       strconv.Itoa(version),
		}

		nsFeatures[i] = database.NamespacedFeature{
			Namespace: namespace,
			Feature:   features[i],
		}
	}

	// insert features
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

func genRandomNamespaces(t *testing.T, count int) []database.Namespace {
	r := make([]database.Namespace, count)
	for i := 0; i < count; i++ {
		r[i] = database.Namespace{
			Name:          uuid.New(),
			VersionFormat: "dpkg",
		}
	}
	return r
}

func TestCaching(t *testing.T) {
	store, err := openDatabaseForTest("Caching", false)
	if !assert.Nil(t, err) {
		t.FailNow()
	}
	defer store.Close()

	nsFeatures, vulnerabilities := testGenRandomVulnerabilityAndNamespacedFeature(t, store)

	fmt.Printf("%d features, %d vulnerabilities are generated", len(nsFeatures), len(vulnerabilities))

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		tx, err := store.Begin()
		if !assert.Nil(t, err) {
			t.FailNow()
		}

		assert.Nil(t, tx.PersistNamespacedFeatures(nsFeatures))
		fmt.Println("finished to insert namespaced features")

		tx.Commit()
	}()

	go func() {
		defer wg.Done()
		tx, err := store.Begin()
		if !assert.Nil(t, err) {
			t.FailNow()
		}

		assert.Nil(t, tx.InsertVulnerabilities(vulnerabilities))
		fmt.Println("finished to insert vulnerabilities")
		tx.Commit()

	}()

	wg.Wait()

	tx, err := store.Begin()
	if !assert.Nil(t, err) {
		t.FailNow()
	}
	defer tx.Rollback()

	// Verify consistency now.
	affected, err := tx.FindAffectedNamespacedFeatures(nsFeatures)
	if !assert.Nil(t, err) {
		t.FailNow()
	}

	for _, ansf := range affected {
		if !assert.True(t, ansf.Valid) {
			t.FailNow()
		}

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

		assert.Len(t, strutil.CompareStringLists(expectedAffectedNames, actualAffectedNames), 0)
		assert.Len(t, strutil.CompareStringLists(actualAffectedNames, expectedAffectedNames), 0)
	}
}
