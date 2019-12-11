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

package modulerpm

import (
	"testing"

	"github.com/quay/clair/v3/database"
	"github.com/quay/clair/v3/ext/featurefmt"
	"github.com/quay/clair/v3/ext/versionfmt/modulerpm"
)

func TestModuleRpmFeatureDetection(t *testing.T) {
	for _, test := range []featurefmt.TestCase{
		{
			"Module rpm test",
			map[string]string{"var/lib/rpm/Packages": "modulerpm/testdata/module_rpm_db"},
			[]database.LayerFeature{
				{
					Feature: database.Feature{
						Name:          "npm",
						Version:       "1:6.9.0-1.10.16.3.2.module+el8.0.0+4214+49953fda",
						VersionFormat: "module-rpm",
						Type:          "binary",
					},
					PotentialNamespace: database.Namespace{Name: "nodejs:10", VersionFormat: modulerpm.ParserName},
				},
				{
					Feature: database.Feature{
						Name:          "nodejs",
						Version:       "1:10.16.3-2.module+el8.0.0+4214+49953fda",
						VersionFormat: "module-rpm",
						Type:          "binary",
					},
					PotentialNamespace: database.Namespace{Name: "nodejs:10", VersionFormat: modulerpm.ParserName},
				},
			},
		},
	} {
		featurefmt.RunTest(t, test, lister{}, modulerpm.ParserName)
	}
}
