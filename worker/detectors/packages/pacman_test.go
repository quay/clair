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

package packages

import (
	"testing"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/utils/types"
)

var pacmanPackagesTests = []packagesTest{
	packagesTest{
		packages: []*database.Package{
			&database.Package{
				Name:    "pam",
				Version: types.NewVersionUnsafe("1.2.1-1"),
			},
			&database.Package{
				Name:    "emacs",
				Version: types.NewVersionUnsafe("24.5-2"),
			},
			&database.Package{
				Name:    "gcc",
				Version: types.NewVersionUnsafe("5.2.0-2"),
			},
		},
		data: map[string][]byte{
			"var/lib/pacman": []byte("testdata/archlinux"),
		},
	},
}

func TestPacmanPackagesDetector(t *testing.T) {
	if checkPackageManager("pacman") != nil {
		log.Warningf("could not find Pacman executable. skipping")
		return
	}

	testPackagesDetector(t, &PacmanPackagesDetector{}, pacmanPackagesTests)
}
