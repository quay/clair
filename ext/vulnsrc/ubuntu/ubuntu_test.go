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

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/ext/versionfmt"
	"github.com/coreos/clair/ext/versionfmt/dpkg"
)

func TestUbuntuParser(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	path := filepath.Join(filepath.Dir(filename))

	// Test parsing testdata/fetcher_
	testData, _ := os.Open(filepath.Join(path, "/testdata/fetcher_ubuntu_test.txt"))
	defer testData.Close()
	vulnerability, unknownReleases, err := parseUbuntuCVE(testData)
	if assert.Nil(t, err) {
		assert.Equal(t, "CVE-2015-4471", vulnerability.Name)
		assert.Equal(t, database.MediumSeverity, vulnerability.Severity)
		assert.Equal(t, "Off-by-one error in the lzxd_decompress function in lzxd.c in libmspack before 0.5 allows remote attackers to cause a denial of service (buffer under-read and application crash) via a crafted CAB archive.", vulnerability.Description)

		// Unknown release (line 28)
		_, hasUnkownRelease := unknownReleases["unknown"]
		assert.True(t, hasUnkownRelease)

		expectedFeatures := []database.AffectedFeature{
			{
				FeatureType: affectedType,
				Namespace: database.Namespace{
					Name:          "ubuntu:14.04",
					VersionFormat: dpkg.ParserName,
				},
				FeatureName:     "libmspack",
				AffectedVersion: versionfmt.MaxVersion,
			},
			{
				FeatureType: affectedType,
				Namespace: database.Namespace{
					Name:          "ubuntu:15.04",
					VersionFormat: dpkg.ParserName,
				},
				FeatureName:     "libmspack",
				FixedInVersion:  "0.4-3",
				AffectedVersion: "0.4-3",
			},
			{
				FeatureType: affectedType,
				Namespace: database.Namespace{
					Name:          "ubuntu:15.10",
					VersionFormat: dpkg.ParserName,
				},
				FeatureName:     "libmspack-anotherpkg",
				FixedInVersion:  "0.1",
				AffectedVersion: "0.1",
			},
		}

		for _, expectedFeature := range expectedFeatures {
			assert.Contains(t, vulnerability.Affected, expectedFeature)
		}
	}
}
