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

package rpm

import (
	"testing"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/utils/types"
	"github.com/coreos/clair/worker/detectors/feature"
)

var rpmPackagesTests = []feature.FeatureVersionTest{
	// Test a CentOS 7 RPM database
	// Memo: Use the following command on a RPM-based system to shrink a database: rpm -qa --qf "%{NAME}\n" |tail -n +3| xargs rpm -e --justdb
	{
		FeatureVersions: []database.FeatureVersion{
			// Two packages from this source are installed, it should only appear once
			{
				Feature: database.Feature{Name: "centos-release"},
				Version: types.NewVersionUnsafe("7-1.1503.el7.centos.2.8"),
			},
			// Two packages from this source are installed, it should only appear once
			{
				Feature: database.Feature{Name: "filesystem"},
				Version: types.NewVersionUnsafe("3.2-18.el7"),
			},
		},
		Data: map[string][]byte{
			"var/lib/rpm/Packages": feature.LoadFileForTest("rpm/testdata/Packages"),
		},
	},
}

func TestRpmFeaturesDetector(t *testing.T) {
	feature.TestFeaturesDetector(t, &RpmFeaturesDetector{}, rpmPackagesTests)
}
