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

package ubuntu

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/quay/clair/v3/database"
	"github.com/quay/clair/v3/ext/versionfmt"
	"github.com/quay/clair/v3/ext/versionfmt/dpkg"
)

func TestUbuntuParser(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	path := filepath.Join(filepath.Dir(filename))

	// Test parsing testdata/fetcher_openubuntu_test.1.xml
	testFile, _ := os.Open(path + "/testdata/fetcher_ubuntu_test.xml")
	defer testFile.Close()

	vulnerabilities, generationTime, err := parseOval(testFile)
	assert.Nil(t, err)
	assert.Equal(t, int64(1565935750), generationTime)

	if assert.Nil(t, err) && assert.Len(t, vulnerabilities, 1) {
		var vulnerability = vulnerabilities[0]
		assert.Equal(t, "CVE-2015-4471", vulnerability.Name)
		assert.Equal(t, database.MediumSeverity, vulnerability.Severity)
		assert.Equal(t, "Off-by-one error in the lzxd_decompress function in lzxd.c in libmspack before 0.5 allows remote attackers to cause a denial of service (buffer under-read and application crash) via a crafted CAB archive. It was discovered that cabextract incorrectly handled certain malformed CAB files. A remote attacker could use this issue to cause cabextract to crash, resulting in a denial of service.", vulnerability.Description)
		assert.Equal(t, "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-4471", vulnerability.Link)

		expectedFeatures := []database.AffectedFeature{
			{
				FeatureType: database.BinaryPackage,
				Namespace: database.Namespace{
					Name:          "ubuntu:xenial",
					VersionFormat: dpkg.ParserName,
				},
				FeatureName:     "libmspack",
				FixedInVersion:  "0.4-3",
				AffectedVersion: "0.4-3",
			},
			{
				FeatureType: database.BinaryPackage,
				Namespace: database.Namespace{
					Name:          "ubuntu:xenial",
					VersionFormat: dpkg.ParserName,
				},
				FeatureName:     "cabextract",
				AffectedVersion: versionfmt.MaxVersion,
			},
		}

		for _, expectedFeature := range expectedFeatures {
			assert.Contains(t, vulnerability.Affected, expectedFeature)
		}
	}
}
