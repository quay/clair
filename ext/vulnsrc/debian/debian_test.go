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

package debian

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/ext/versionfmt"
	"github.com/coreos/clair/ext/versionfmt/dpkg"
	"github.com/stretchr/testify/assert"
)

func TestDebianParser(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)

	// Test parsing testdata/fetcher_debian_test.json
	testFile, _ := os.Open(filepath.Join(filepath.Dir(filename), "/testdata/fetcher_debian_test.json"))
	response, err := buildResponse(testFile, "")
	if assert.Nil(t, err) && assert.Len(t, response.Vulnerabilities, 2) {
		for _, vulnerability := range response.Vulnerabilities {
			if vulnerability.Name == "CVE-2015-1323" {
				assert.Equal(t, "https://security-tracker.debian.org/tracker/CVE-2015-1323", vulnerability.Link)
				assert.Equal(t, database.LowSeverity, vulnerability.Severity)
				assert.Equal(t, "This vulnerability is not very dangerous.", vulnerability.Description)

				expectedFeatures := []database.AffectedFeature{
					{
						FeatureType: affectedType,
						Namespace: database.Namespace{
							Name:          "debian:8",
							VersionFormat: dpkg.ParserName,
						},
						FeatureName:     "aptdaemon",
						AffectedVersion: versionfmt.MaxVersion,
					},
					{
						FeatureType: affectedType,
						Namespace: database.Namespace{
							Name:          "debian:unstable",
							VersionFormat: dpkg.ParserName,
						},
						FeatureName:     "aptdaemon",
						AffectedVersion: "1.1.1+bzr982-1",
						FixedInVersion:  "1.1.1+bzr982-1",
					},
				}

				for _, expectedFeature := range expectedFeatures {
					assert.Contains(t, vulnerability.Affected, expectedFeature)
				}
			} else if vulnerability.Name == "CVE-2003-0779" {
				assert.Equal(t, "https://security-tracker.debian.org/tracker/CVE-2003-0779", vulnerability.Link)
				assert.Equal(t, database.HighSeverity, vulnerability.Severity)
				assert.Equal(t, "But this one is very dangerous.", vulnerability.Description)

				expectedFeatures := []database.AffectedFeature{
					{
						FeatureType: affectedType,
						Namespace: database.Namespace{
							Name:          "debian:8",
							VersionFormat: dpkg.ParserName,
						},
						FeatureName:     "aptdaemon",
						FixedInVersion:  "0.7.0",
						AffectedVersion: "0.7.0",
					},
					{
						FeatureType: affectedType,
						Namespace: database.Namespace{
							Name:          "debian:unstable",
							VersionFormat: dpkg.ParserName,
						},
						FeatureName:     "aptdaemon",
						FixedInVersion:  "0.7.0",
						AffectedVersion: "0.7.0",
					},
					{
						FeatureType: affectedType,
						Namespace: database.Namespace{
							Name:          "debian:8",
							VersionFormat: dpkg.ParserName,
						},
						FeatureName:     "asterisk",
						FixedInVersion:  "0.5.56",
						AffectedVersion: "0.5.56",
					},
				}

				for _, expectedFeature := range expectedFeatures {
					assert.Contains(t, vulnerability.Affected, expectedFeature)
				}
			} else {
				assert.Fail(t, "Wrong vulnerability name: ", vulnerability.Namespace.Name+":"+vulnerability.Name)
			}
		}
	}
}
