// Copyright 2015 quay-sec authors
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

package packages

import (
	"testing"

	"github.com/coreos/quay-sec/database"
	"github.com/coreos/quay-sec/utils/types"
)

var dpkgPackagesTests = []packagesTest{
	// Test an Ubuntu dpkg status file
	packagesTest{
		packages: []*database.Package{
			&database.Package{
				Name:    "pam", // Two packages from this source are installed, it should only appear one time
				Version: types.NewVersionUnsafe("1.1.8-3.1ubuntu3"),
			},
			&database.Package{
				Name:    "makedev",                                 // The source name and the package name are equals
				Version: types.NewVersionUnsafe("2.3.1-93ubuntu1"), // The version comes from the "Version:" line
			},
			&database.Package{
				Name:    "gcc-5",
				Version: types.NewVersionUnsafe("5.1.1-12ubuntu1"), // The version comes from the "Source:" line
			},
		},
		data: map[string][]byte{
			"var/lib/dpkg/status": loadFileForTest("testdata/dpkg_status"),
		},
	},
}

func TestDpkgPackagesDetector(t *testing.T) {
	testPackagesDetector(t, &DpkgPackagesDetector{}, dpkgPackagesTests)
}
