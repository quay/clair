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
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/ext/versionfmt/rpm"
	"github.com/stretchr/testify/assert"
)

func TestOracleParser(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	path := filepath.Join(filepath.Dir(filename))

	// Test parsing testdata/fetcher_oracle_test.1.xml
	testFile, _ := os.Open(path + "/testdata/fetcher_oracle_test.1.xml")
	defer testFile.Close()

	vulnerabilities, err := parseELSA(testFile)
	if assert.Nil(t, err) && assert.Len(t, vulnerabilities, 1) {
		assert.Equal(t, "ELSA-2015-1193", vulnerabilities[0].Name)
		assert.Equal(t, "http://linux.oracle.com/errata/ELSA-2015-1193.html", vulnerabilities[0].Link)
		assert.Equal(t, database.MediumSeverity, vulnerabilities[0].Severity)
		assert.Equal(t, ` [3.1.1-7] Resolves: rhbz#1217104 CVE-2015-0252 `, vulnerabilities[0].Description)

		expectedFeatureVersions := []database.FeatureVersion{
			{
				Feature: database.Feature{
					Namespace: database.Namespace{
						Name:          "oracle:7",
						VersionFormat: rpm.ParserName,
					},
					Name: "xerces-c",
				},
				Version: "0:3.1.1-7.el7_1",
			},
			{
				Feature: database.Feature{
					Namespace: database.Namespace{
						Name:          "oracle:7",
						VersionFormat: rpm.ParserName,
					},
					Name: "xerces-c-devel",
				},
				Version: "0:3.1.1-7.el7_1",
			},
			{
				Feature: database.Feature{
					Namespace: database.Namespace{
						Name:          "oracle:7",
						VersionFormat: rpm.ParserName,
					},
					Name: "xerces-c-doc",
				},
				Version: "0:3.1.1-7.el7_1",
			},
		}

		for _, expectedFeatureVersion := range expectedFeatureVersions {
			assert.Contains(t, vulnerabilities[0].FixedIn, expectedFeatureVersion)
		}
	}

	testFile2, _ := os.Open(path + "/testdata/fetcher_oracle_test.2.xml")
	defer testFile2.Close()

	vulnerabilities, err = parseELSA(testFile2)
	if assert.Nil(t, err) && assert.Len(t, vulnerabilities, 1) {
		assert.Equal(t, "ELSA-2015-1207", vulnerabilities[0].Name)
		assert.Equal(t, "http://linux.oracle.com/errata/ELSA-2015-1207.html", vulnerabilities[0].Link)
		assert.Equal(t, database.CriticalSeverity, vulnerabilities[0].Severity)
		assert.Equal(t, ` [38.1.0-1.0.1.el7_1] - Add firefox-oracle-default-prefs.js and remove the corresponding Red Hat file [38.1.0-1] - Update to 38.1.0 ESR [38.0.1-2] - Fixed rhbz#1222807 by removing preun section `, vulnerabilities[0].Description)
		expectedFeatureVersions := []database.FeatureVersion{
			{
				Feature: database.Feature{
					Namespace: database.Namespace{
						Name:          "oracle:6",
						VersionFormat: rpm.ParserName,
					},
					Name: "firefox",
				},
				Version: "0:38.1.0-1.0.1.el6_6",
			},
			{
				Feature: database.Feature{
					Namespace: database.Namespace{
						Name:          "oracle:7",
						VersionFormat: rpm.ParserName,
					},
					Name: "firefox",
				},
				Version: "0:38.1.0-1.0.1.el7_1",
			},
		}

		for _, expectedFeatureVersion := range expectedFeatureVersions {
			assert.Contains(t, vulnerabilities[0].FixedIn, expectedFeatureVersion)
		}
	}
}
