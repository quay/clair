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

package sle

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/utils/oval"
	"github.com/coreos/clair/utils/types"
	"github.com/stretchr/testify/assert"
)

func TestSLEParser(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	path := filepath.Join(filepath.Dir(filename))

	// Test parsing testdata/fetcher_sle_test.1.xml
	testFile, _ := os.Open(path + "/testdata/fetcher_sle_test.1.xml")
	ov := &oval.OvalFetcher{OsInfo: &SLEInfo{}}
	vulnerabilities, err := ov.ParseOval(testFile)
	if assert.Nil(t, err) && assert.Len(t, vulnerabilities, 1) {
		assert.Equal(t, "CVE-2012-2150", vulnerabilities[0].Name)
		assert.Equal(t, "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-2150", vulnerabilities[0].Link)
		// Severity is not defined for SLE
		assert.Equal(t, types.Unknown, vulnerabilities[0].Severity)
		assert.Equal(t, `xfs_metadump in xfsprogs before 3.2.4 does not properly obfuscate file data, which allows remote attackers to obtain sensitive information by reading a generated image.`, vulnerabilities[0].Description)

		expectedFeatureVersions := []database.FeatureVersion{
			{
				Feature: database.Feature{
					Namespace: database.Namespace{Name: "sle:12"},
					Name:      "xfsprogs",
				},
				Version: types.NewVersionUnsafe("3.2.1-3.5"),
			},
			{
				Feature: database.Feature{
					Namespace: database.Namespace{Name: "sle:12.1"},
					Name:      "xfsprogs",
				},
				Version: types.NewVersionUnsafe("3.2.1-3.5"),
			},
		}

		for _, expectedFeatureVersion := range expectedFeatureVersions {
			assert.Contains(t, vulnerabilities[0].FixedIn, expectedFeatureVersion)
		}

	}

}
