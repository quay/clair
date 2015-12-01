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

func TestUbuntuParser(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	path := path.Join(path.Dir(filename))

	// Test parsing testdata/fetcher_
	testData, _ := os.Open(path + "/testdata/fetcher_ubuntu_test.txt")
	defer testData.Close()
	vulnerability, packages, unknownReleases, err := parseUbuntuCVE(testData)
	if assert.Nil(t, err) {
		assert.Equal(t, "CVE-2015-4471", vulnerability.ID)
		assert.Equal(t, types.Medium, vulnerability.Priority)
		assert.Equal(t, "Off-by-one error in the lzxd_decompress function in lzxd.c in libmspack before 0.5 allows remote attackers to cause a denial of service (buffer under-read and application crash) via a crafted CAB archive.", vulnerability.Description)

		// Unknown release (line 28)
		_, hasUnkownRelease := unknownReleases["unknown"]
		assert.True(t, hasUnkownRelease)

		expectedPackages := []*database.Package{
			&database.Package{
				OS:      "ubuntu:14.04",
				Name:    "libmspack",
				Version: types.MaxVersion,
			},
			&database.Package{
				OS:      "ubuntu:15.04",
				Name:    "libmspack",
				Version: types.NewVersionUnsafe("0.4-3"),
			},
			&database.Package{
				OS:      "ubuntu:15.10",
				Name:    "libmspack-anotherpkg",
				Version: types.NewVersionUnsafe("0.1"),
			},
		}

		for _, expectedPackage := range expectedPackages {
			assert.Contains(t, packages, expectedPackage)
			assert.Contains(t, vulnerability.FixedInNodes, expectedPackage.GetNode())
		}
	}
}
