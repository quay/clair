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

package dpkg

import (
	"testing"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/ext/featurefmt"
	"github.com/coreos/clair/pkg/tarutil"
)

func TestDpkgFeatureDetection(t *testing.T) {
	testData := []featurefmt.TestData{
		// Test an Ubuntu dpkg status file
		{
			FeatureVersions: []database.FeatureVersion{
				// Two packages from this source are installed, it should only appear one time
				{
					Feature: database.Feature{Name: "pam"},
					Version: "1.1.8-3.1ubuntu3",
				},
				{
					Feature: database.Feature{Name: "makedev"}, // The source name and the package name are equals
					Version: "2.3.1-93ubuntu1",                 // The version comes from the "Version:" line
				},
				{
					Feature: database.Feature{Name: "gcc-5"},
					Version: "5.1.1-12ubuntu1", // The version comes from the "Source:" line
				},
			},
			Files: tarutil.FilesMap{
				"var/lib/dpkg/status": featurefmt.LoadFileForTest("dpkg/testdata/status"),
			},
		},
	}

	featurefmt.TestLister(t, &lister{}, testData)
}
