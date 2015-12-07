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

package database

import (
	"math/rand"
	"sort"
	"testing"
	"time"

	"github.com/coreos/clair/config"
	"github.com/coreos/clair/utils/types"
	"github.com/stretchr/testify/assert"
)

func TestPackage(t *testing.T) {
	Open(&config.DatabaseConfig{Type: "memstore"})
	defer Close()

	// Try to insert invalid packages
	for _, invalidPkg := range []*Package{
		&Package{OS: "", Name: "testpkg1", Version: types.NewVersionUnsafe("1.0")},
		&Package{OS: "testOS", Name: "", Version: types.NewVersionUnsafe("1.0")},
		&Package{OS: "testOS", Name: "testpkg1", Version: types.NewVersionUnsafe("")},
		&Package{OS: "testOS", Name: "testpkg1", Version: types.NewVersionUnsafe("bad version")},
		&Package{OS: "", Name: "", Version: types.NewVersionUnsafe("")},
	} {
		err := InsertPackages([]*Package{invalidPkg})
		assert.Error(t, err)
	}

	// Insert a package
	pkg1 := &Package{OS: "testOS", Name: "testpkg1", Version: types.NewVersionUnsafe("1.0")}
	err := InsertPackages([]*Package{pkg1})
	if assert.Nil(t, err) {
		// Find the inserted package and verify its content
		pkg1b, err := FindOnePackage(pkg1.OS, pkg1.Name, pkg1.Version, FieldPackageAll)
		if assert.Nil(t, err) && assert.NotNil(t, pkg1b) {
			assert.Equal(t, pkg1.Node, pkg1b.Node)
			assert.Equal(t, pkg1.OS, pkg1b.OS)
			assert.Equal(t, pkg1.Name, pkg1b.Name)
			assert.Equal(t, pkg1.Version, pkg1b.Version)
		}

		// Find packages from the inserted branch and verify their content
		// (the first one should be a start package, the second one the inserted one and the third one the end package)
		pkgs1c, err := FindAllPackagesByBranch(pkg1.OS, pkg1.Name, FieldPackageAll)
		if assert.Nil(t, err) && assert.Equal(t, 3, len(pkgs1c)) {
			sort.Sort(ByVersion(pkgs1c))

			assert.Equal(t, pkg1.OS, pkgs1c[0].OS)
			assert.Equal(t, pkg1.Name, pkgs1c[0].Name)
			assert.Equal(t, types.MinVersion, pkgs1c[0].Version)

			assert.Equal(t, pkg1.OS, pkgs1c[1].OS)
			assert.Equal(t, pkg1.Name, pkgs1c[1].Name)
			assert.Equal(t, pkg1.Version, pkgs1c[1].Version)

			assert.Equal(t, pkg1.OS, pkgs1c[2].OS)
			assert.Equal(t, pkg1.Name, pkgs1c[2].Name)
			assert.Equal(t, types.MaxVersion, pkgs1c[2].Version)
		}
	}

	// Insert multiple packages in the same branch, one in another branch, insert local duplicates and database duplicates as well
	pkg2 := []*Package{
		&Package{OS: "testOS", Name: "testpkg1", Version: types.NewVersionUnsafe("0.8")},
		&Package{OS: "testOS", Name: "testpkg1", Version: types.NewVersionUnsafe("0.9")},
		&Package{OS: "testOS", Name: "testpkg1", Version: types.NewVersionUnsafe("1.0")}, // Already present in the database
		&Package{OS: "testOS", Name: "testpkg1", Version: types.NewVersionUnsafe("1.1")},
		&Package{OS: "testOS", Name: "testpkg2", Version: types.NewVersionUnsafe("1.0")}, // Another branch
		&Package{OS: "testOS", Name: "testpkg2", Version: types.NewVersionUnsafe("1.0")}, // Local duplicates
	}
	nbInSameBranch := 4 + 2 // (start/end packages)

	err = InsertPackages(shuffle(pkg2))
	if assert.Nil(t, err) {
		// Find packages from the inserted branch, verify their order and NextVersion / PreviousVersion
		pkgs2b, err := FindAllPackagesByBranch("testOS", "testpkg1", FieldPackageAll)
		if assert.Nil(t, err) && assert.Equal(t, nbInSameBranch, len(pkgs2b)) {
			sort.Sort(ByVersion(pkgs2b))

			for i := 0; i < nbInSameBranch; i = i + 1 {
				if i == 0 {
					assert.Equal(t, types.MinVersion, pkgs2b[0].Version)
				} else if i < nbInSameBranch-2 {
					assert.Equal(t, pkg2[i].Version, pkgs2b[i+1].Version)

					nv, err := pkgs2b[i+1].NextVersion(FieldPackageAll)
					assert.Nil(t, err)
					assert.Equal(t, pkgs2b[i+2], nv)

					if i > 0 {
						pv, err := pkgs2b[i].PreviousVersion(FieldPackageAll)
						assert.Nil(t, err)
						assert.Equal(t, pkgs2b[i-1], pv)
					} else {
						pv, err := pkgs2b[i].PreviousVersion(FieldPackageAll)
						assert.Nil(t, err)
						assert.Nil(t, pv)
					}
				} else {
					assert.Equal(t, types.MaxVersion, pkgs2b[nbInSameBranch-1].Version)

					nv, err := pkgs2b[nbInSameBranch-1].NextVersion(FieldPackageAll)
					assert.Nil(t, err)
					assert.Nil(t, nv)

					pv, err := pkgs2b[i].PreviousVersion(FieldPackageAll)
					assert.Nil(t, err)
					assert.Equal(t, pkgs2b[i-1], pv)
				}
			}

			// NextVersions
			nv, err := pkgs2b[0].NextVersions(FieldPackageAll)
			if assert.Nil(t, err) && assert.Len(t, nv, nbInSameBranch-1) {
				for i := 0; i < nbInSameBranch-1; i = i + 1 {
					if i < nbInSameBranch-2 {
						assert.Equal(t, pkg2[i].Version, nv[i].Version)
					} else {
						assert.Equal(t, types.MaxVersion, nv[i].Version)
					}
				}
			}

			// PreviousVersions
			pv, err := pkgs2b[nbInSameBranch-1].PreviousVersions(FieldPackageAll)
			if assert.Nil(t, err) && assert.Len(t, pv, nbInSameBranch-1) {
				for i := 0; i < len(pv); i = i + 1 {
					assert.Equal(t, pkgs2b[len(pkgs2b)-i-2], pv[i])
				}
			}
		}

		// Verify that the one we added which was already present in the database has the same node value (meaning that we just fetched it actually)
		assert.Contains(t, pkg2, pkg1)
	}

	// Insert duplicated latest packages directly, ensure only one is actually inserted. Then insert another package in the branch and ensure that its next version is the latest one
	pkg3a := &Package{OS: "testOS", Name: "testpkg3", Version: types.MaxVersion}
	pkg3b := &Package{OS: "testOS", Name: "testpkg3", Version: types.MaxVersion}
	pkg3c := &Package{OS: "testOS", Name: "testpkg3", Version: types.MaxVersion}
	err1 := InsertPackages([]*Package{pkg3a, pkg3b})
	err2 := InsertPackages([]*Package{pkg3c})
	if assert.Nil(t, err1) && assert.Nil(t, err2) {
		assert.Equal(t, pkg3a, pkg3b)
		assert.Equal(t, pkg3b, pkg3c)
	}
	pkg4 := Package{OS: "testOS", Name: "testpkg3", Version: types.NewVersionUnsafe("1.0")}
	InsertPackages([]*Package{&pkg4})
	pkgs34, _ := FindAllPackagesByBranch("testOS", "testpkg3", FieldPackageAll)
	if assert.Len(t, pkgs34, 3) {
		sort.Sort(ByVersion(pkgs34))
		assert.Equal(t, pkg4.Node, pkgs34[1].Node)
		assert.Equal(t, pkg3a.Node, pkgs34[2].Node)
		assert.Equal(t, pkg3a.Node, pkgs34[1].NextVersionNode)
	}

	// Insert two identical packages but with "different" versions
	// The second version should be simplified to the first one
	// Therefore, we should just have three packages (the inserted one and the start/end packages of the branch)
	InsertPackages([]*Package{&Package{OS: "testOS", Name: "testdirtypkg", Version: types.NewVersionUnsafe("0.1")}})
	InsertPackages([]*Package{&Package{OS: "testOS", Name: "testdirtypkg", Version: types.NewVersionUnsafe("0:0.1")}})
	dirtypkgs, err := FindAllPackagesByBranch("testOS", "testdirtypkg", FieldPackageAll)
	assert.Nil(t, err)
	assert.Len(t, dirtypkgs, 3)
}

func shuffle(packageParameters []*Package) []*Package {
	rand.Seed(int64(time.Now().Nanosecond()))

	sPackage := make([]*Package, len(packageParameters))
	copy(sPackage, packageParameters)

	for i := len(sPackage) - 1; i > 0; i-- {
		j := rand.Intn(i)
		sPackage[i], sPackage[j] = sPackage[j], sPackage[i]
	}

	return sPackage
}
