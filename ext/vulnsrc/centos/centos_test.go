// Copyright 2019
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

package centos

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/ext/versionfmt/rpm"
	"github.com/stretchr/testify/assert"
)

func TestCESAParser(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	path := filepath.Join(filepath.Dir(filename))

	// Test parsing testdata/mini_errata.xml
	testFile, _ := os.Open(path + "/testdata/mini_cesa_errata.xml")
	m := make(map[string][]string)
	m["RHSA-2018:2881"] = []string{"CVE-2018-12386", "CVE-2018-12387"}
	data, err := ioutil.ReadAll(testFile)

	vulnerabilities, _, err := parseCESA(string(data), m)
	fmt.Println(vulnerabilities)

	if assert.Nil(t, err) && assert.Len(t, vulnerabilities, 2) {
		assert.Equal(t, "CVE-2018-12386", vulnerabilities[0].Name)
		assert.Equal(t, "CVE-2018-12387", vulnerabilities[1].Name)
		assert.Equal(t, "https://access.redhat.com/errata/RHSA-2018:2881", vulnerabilities[0].Link)
		assert.Equal(t, "https://access.redhat.com/errata/RHSA-2018:2881", vulnerabilities[1].Link)
		assert.Equal(t, database.CriticalSeverity, vulnerabilities[0].Severity)
		assert.Equal(t, database.CriticalSeverity, vulnerabilities[1].Severity)
		assert.Equal(t, `Not available`, vulnerabilities[0].Description)
		assert.Equal(t, `Not available`, vulnerabilities[1].Description)

		expectedFeatureVersion := database.FeatureVersion{
			Feature: database.Feature{
				Namespace: database.Namespace{
					Name:          "centos:6",
					VersionFormat: rpm.ParserName,
				},
				Name: "firefox",
			},
			Version: "60.2.2-1.el6",
		}

		assert.Contains(t, vulnerabilities[0].FixedIn, expectedFeatureVersion)
		assert.Contains(t, vulnerabilities[1].FixedIn, expectedFeatureVersion)
	}
}
