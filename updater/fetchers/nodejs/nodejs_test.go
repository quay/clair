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

package nodejs

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/utils/types"
	"github.com/stretchr/testify/assert"
)

func TestNodejsParser(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	testFile, _ := os.Open(filepath.Join(filepath.Dir(filename)) + "/testdata/fetcher_nodejs_test.json")
	defer testFile.Close()

	var advisories nodejsAdvisories
	json.NewDecoder(testFile).Decode(&advisories)
	assert.Len(t, advisories.Results, 4)

	vulnerabilities, lastUpdated := parseNodejsAdvisories(advisories.Results, "")
	assert.Len(t, vulnerabilities, 2)
	assert.Equal(t, "2016-05-13T20:39:38+00:00", lastUpdated)

	for _, vulnerability := range vulnerabilities {
		if vulnerability.Name == "CVE-2015-7294" {
			assert.Equal(t, "http://cve.mitre.org/cgi-bin/cvename.cgi?name=2015-7294", vulnerability.Link)
			assert.Equal(t, types.Medium, vulnerability.Severity)
			assert.Equal(t, "ldapauth versions <= 2.2.4 are vulnerable to ldap injection through the username parameter.", vulnerability.Description)
			expectedFeatureVersions := []database.FeatureVersion{
				{
					Feature: database.Feature{
						Namespace: database.Namespace{Name: "nodejs:" + defaultNodejsVersion},
						Name:      "ldapauth",
					},
					Version: types.NewVersionUnsafe("2.2.4" + defaultVersionSuffix),
				},
				{
					Feature: database.Feature{
						Namespace: database.Namespace{Name: "nodejs:" + defaultNodejsVersion},
						Name:      "ldapauth-fork",
					},
					Version: types.NewVersionUnsafe("2.3.3"),
				},
			}
			for _, expectedFeatureVersion := range expectedFeatureVersions {
				assert.Contains(t, vulnerability.FixedIn, expectedFeatureVersion)
			}
		} else if vulnerability.Name == "CVE-2016-2515" {
			assert.Equal(t, "http://cve.mitre.org/cgi-bin/cvename.cgi?name=2016-2515", vulnerability.Link)
			assert.Equal(t, types.Medium, vulnerability.Severity)
			assert.Equal(t, "Specifically crafted long headers or uris can cause a minor denial of service when using hawk versions less than 4.1.1.\n\n\"The Regular expression Denial of Service (ReDoS) is a Denial of Service attack, that exploits the fact that most Regular Expression implementations may reach extreme situations that cause them to work very slowly (exponentially related to input size). An attacker can then cause a program using a Regular Expression to enter these extreme situations and then hang for a very long time.\"\n\nUpdates:\n- Updated to include fix in 3.1.3 ", vulnerability.Description)
			expectedFeatureVersions := []database.FeatureVersion{
				{
					Feature: database.Feature{
						Namespace: database.Namespace{Name: "nodejs:" + defaultNodejsVersion},
						Name:      "hawk",
					},
					Version: types.NewVersionUnsafe("4.1.1"),
				},
			}
			for _, expectedFeatureVersion := range expectedFeatureVersions {
				assert.Contains(t, vulnerability.FixedIn, expectedFeatureVersion)
			}
		}
	}

	return
}
