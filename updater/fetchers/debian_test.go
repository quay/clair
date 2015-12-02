// Copyright 2015 clair authors
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

package fetchers

import (
	"os"
	"path"
	"runtime"
	"testing"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/utils/types"
	"github.com/stretchr/testify/assert"
)

func TestDebianParser(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)

	// Test parsing testdata/fetcher_debian_test.json
	testFile, _ := os.Open(path.Join(path.Dir(filename)) + "/testdata/fetcher_debian_test.json")
	response, err := buildResponse(testFile, "")
	if assert.Nil(t, err) && assert.Len(t, response.Vulnerabilities, 2) {
		for _, vulnerability := range response.Vulnerabilities {
			if vulnerability.ID == "CVE-2015-1323" {
				assert.Equal(t, "https://security-tracker.debian.org/tracker/CVE-2015-1323", vulnerability.Link)
				assert.Equal(t, types.Low, vulnerability.Priority)
				assert.Equal(t, "This vulnerability is not very dangerous.", vulnerability.Description)

				expectedPackages := []*database.Package{
					&database.Package{
						OS:      "debian:8",
						Name:    "aptdaemon",
						Version: types.MaxVersion,
					},
					&database.Package{
						OS:      "debian:unstable",
						Name:    "aptdaemon",
						Version: types.NewVersionUnsafe("1.1.1+bzr982-1"),
					},
				}

				for _, expectedPackage := range expectedPackages {
					assert.Contains(t, response.Packages, expectedPackage)
					assert.Contains(t, vulnerability.FixedInNodes, expectedPackage.GetNode())
				}
			} else if vulnerability.ID == "CVE-2003-0779" {
				assert.Equal(t, "https://security-tracker.debian.org/tracker/CVE-2003-0779", vulnerability.Link)
				assert.Equal(t, types.High, vulnerability.Priority)
				assert.Equal(t, "But this one is very dangerous.", vulnerability.Description)

				expectedPackages := []*database.Package{
					&database.Package{
						OS:      "debian:8",
						Name:    "aptdaemon",
						Version: types.NewVersionUnsafe("0.7.0"),
					},
					&database.Package{
						OS:      "debian:unstable",
						Name:    "aptdaemon",
						Version: types.NewVersionUnsafe("0.7.0"),
					},
					&database.Package{
						OS:      "debian:8",
						Name:    "asterisk",
						Version: types.NewVersionUnsafe("0.5.56"),
					},
				}

				for _, expectedPackage := range expectedPackages {
					assert.Contains(t, response.Packages, expectedPackage)
					assert.Contains(t, vulnerability.FixedInNodes, expectedPackage.GetNode())
				}
			} else {
				assert.Fail(t, "Wrong vulnerability name: ", vulnerability.ID)
			}
		}
	}
}
