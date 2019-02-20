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

package oracle

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/ext/versionfmt/rpm"
	"github.com/stretchr/testify/assert"
)

func TestOracleParserOneCve(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	path := filepath.Join(filepath.Dir(filename))

	// Test parsing testdata/fetcher_oracle_test.1.xml
	testFile, _ := os.Open(filepath.Join(path, "/testdata/fetcher_oracle_test.1.xml"))
	defer testFile.Close()

	vulnerabilities, err := parseELSA(testFile)
	if assert.Nil(t, err) && assert.Len(t, vulnerabilities, 1) {
		assert.Equal(t, "CVE-2015-0252", vulnerabilities[0].Name)
		assert.Equal(t, "http://linux.oracle.com/cve/CVE-2015-0252.html", vulnerabilities[0].Link)
		assert.Equal(t, database.MediumSeverity, vulnerabilities[0].Severity)
		assert.Equal(t, ` [3.1.1-7] Resolves: rhbz#1217104 CVE-2015-0252 `, vulnerabilities[0].Description)

		expectedFeatures := []database.AffectedFeature{
			{
				FeatureType: affectedType,
				Namespace: database.Namespace{
					Name:          "oracle:7",
					VersionFormat: rpm.ParserName,
				},
				FeatureName:     "xerces-c",
				FixedInVersion:  "0:3.1.1-7.el7_1",
				AffectedVersion: "0:3.1.1-7.el7_1",
			},
			{
				FeatureType: affectedType,
				Namespace: database.Namespace{
					Name:          "oracle:7",
					VersionFormat: rpm.ParserName,
				},
				FeatureName:     "xerces-c-devel",
				FixedInVersion:  "0:3.1.1-7.el7_1",
				AffectedVersion: "0:3.1.1-7.el7_1",
			},
			{
				FeatureType: affectedType,
				Namespace: database.Namespace{
					Name:          "oracle:7",
					VersionFormat: rpm.ParserName,
				},
				FeatureName:     "xerces-c-doc",
				FixedInVersion:  "0:3.1.1-7.el7_1",
				AffectedVersion: "0:3.1.1-7.el7_1",
			},
		}

		for _, expectedFeature := range expectedFeatures {
			assert.Contains(t, vulnerabilities[0].Affected, expectedFeature)
		}
	}
}

func TestELSAParserMultipleCVE(t *testing.T) {
	testFile, _ := os.Open("testdata/fetcher_oracle_test.2.xml")
	defer testFile.Close()

	vulnerabilities, err := parseELSA(testFile)

	// Expected
	expectedCve := []string{"CVE-2015-2722", "CVE-2015-2724", "CVE-2015-2725", "CVE-2015-2727",
		"CVE-2015-2728", "CVE-2015-2729", "CVE-2015-2731", "CVE-2015-2733", "CVE-2015-2734",
		"CVE-2015-2735", "CVE-2015-2736", "CVE-2015-2737", "CVE-2015-2738", "CVE-2015-2739",
		"CVE-2015-2740", "CVE-2015-2741", "CVE-2015-2743"}
	expectedSeverity := []string{"Negligible", "Low", "Medium", "High",
		"Critical", "Unknown", "Critical", "Critical", "Critical",
		"Critical", "Critical", "Critical", "Critical", "Critical",
		"Critical", "Critical", "Critical"}

	if assert.Nil(t, err) && assert.Len(t, vulnerabilities, len(expectedCve)) {
		for i, vulnerability := range vulnerabilities {
			assert.Equal(t, expectedCve[i], vulnerability.Name)
			assert.Equal(t, fmt.Sprintf("http://linux.oracle.com/cve/%s.html", expectedCve[i]), vulnerability.Link)
			assert.Equal(t, database.Severity(expectedSeverity[i]), vulnerability.Severity)
			assert.Equal(t, ` [38.1.0-1.0.1.el7_1] - Add firefox-oracle-default-prefs.js and remove the corresponding Red Hat file [38.1.0-1] - Update to 38.1.0 ESR [38.0.1-2] - Fixed rhbz#1222807 by removing preun section `, vulnerability.Description)
		}
	}
}

func TestELSAComparison(t *testing.T) {
	var table = []struct {
		left     int
		right    int
		expected int
	}{
		{20170935, 20170935, 0},
		{20170934, 20170935, -1},
		{20170936, 20170935, 1},

		{20170935, 201709331, 1},
		{201709351, 20170935, 1},
		{201709331, 20170935, -1},
	}

	for _, tt := range table {
		assert.Equal(t, tt.expected, compareELSA(tt.left, tt.right))
	}
}
