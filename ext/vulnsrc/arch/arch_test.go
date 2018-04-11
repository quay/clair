// Copyright 2017-2018 clair authors
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

package arch

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/ext/versionfmt/rpm"

	"github.com/stretchr/testify/assert"
)

func TestArchLinuxParser(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)

	// Test parsing testdata/fetcher_arch_test.json
	testFile, _ := os.Open(filepath.Join(filepath.Dir(filename)) + "/testdata/fetcher_arch_test.json")
	response, err := buildResponse(testFile, "")
	if assert.Nil(t, err) && assert.Len(t, response.Vulnerabilities, 4) {
		for _, vulnerability := range response.Vulnerabilities {
			if vulnerability.Name == "CVE-2018-1071" {
				assert.Equal(t, "https://security.archlinux.org/CVE-2018-1071", vulnerability.Link)
				assert.Equal(t, database.MediumSeverity, vulnerability.Severity)
				assert.Equal(t, "denial of service", vulnerability.Description)

				expectedFeatures := []database.AffectedFeature{
					{
						Namespace: database.Namespace{
							Name:          "arch",
							VersionFormat: rpm.ParserName,
						},
						FeatureName:     "zsh",
						AffectedVersion: "5.4.2-1",
					},
				}

				for _, expectedFeature := range expectedFeatures {
					assert.Contains(t, vulnerability.Affected, expectedFeature)
				}
			} else if vulnerability.Name == "CVE-2018-5146" {
				assert.Equal(t, "https://security.archlinux.org/CVE-2018-5146", vulnerability.Link)
				assert.Equal(t, database.CriticalSeverity, vulnerability.Severity)
				assert.Equal(t, "multiple issues", vulnerability.Description)

				expectedFeatures := []database.AffectedFeature{
					{
						Namespace: database.Namespace{
							Name:          "arch",
							VersionFormat: rpm.ParserName,
						},
						FeatureName:     "libvorbis",
						FixedInVersion:  "1.3.6-1",
						AffectedVersion: "1.3.5-1",
					},
					{
						Namespace: database.Namespace{
							Name:          "arch",
							VersionFormat: rpm.ParserName,
						},
						FeatureName:     "lib32-libvorbis",
						FixedInVersion:  "1.3.6-1",
						AffectedVersion: "1.3.5-1",
					},
				}

				for _, expectedFeature := range expectedFeatures {
					assert.Contains(t, vulnerability.Affected, expectedFeature)
				}
			} else if vulnerability.Name == "CVE-2017-14633" {
				assert.Equal(t, "https://security.archlinux.org/CVE-2017-14633", vulnerability.Link)
				assert.Equal(t, database.CriticalSeverity, vulnerability.Severity)
				assert.Equal(t, "multiple issues", vulnerability.Description)

				expectedFeatures := []database.AffectedFeature{
					{
						Namespace: database.Namespace{
							Name:          "arch",
							VersionFormat: rpm.ParserName,
						},
						FeatureName:     "libvorbis",
						FixedInVersion:  "1.3.6-1",
						AffectedVersion: "1.3.5-1",
					},
					{
						Namespace: database.Namespace{
							Name:          "arch",
							VersionFormat: rpm.ParserName,
						},
						FeatureName:     "lib32-libvorbis",
						FixedInVersion:  "1.3.6-1",
						AffectedVersion: "1.3.5-1",
					},
				}

				for _, expectedFeature := range expectedFeatures {
					assert.Contains(t, vulnerability.Affected, expectedFeature)
				}
			} else if vulnerability.Name == "CVE-2017-14632" {
				assert.Equal(t, "https://security.archlinux.org/CVE-2017-14632", vulnerability.Link)
				assert.Equal(t, database.CriticalSeverity, vulnerability.Severity)
				assert.Equal(t, "multiple issues", vulnerability.Description)

				expectedFeatures := []database.AffectedFeature{
					{
						Namespace: database.Namespace{
							Name:          "arch",
							VersionFormat: rpm.ParserName,
						},
						FeatureName:     "libvorbis",
						FixedInVersion:  "1.3.6-1",
						AffectedVersion: "1.3.5-1",
					},
					{
						Namespace: database.Namespace{
							Name:          "arch",
							VersionFormat: rpm.ParserName,
						},
						FeatureName:     "lib32-libvorbis",
						FixedInVersion:  "1.3.6-1",
						AffectedVersion: "1.3.5-1",
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
