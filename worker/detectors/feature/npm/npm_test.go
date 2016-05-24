// Copyright 2016 clair authors
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

package npm

import (
	"testing"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/utils/types"
	"github.com/coreos/clair/worker/detectors/feature"
)

var npmPackagesTests = []feature.FeatureVersionTest{
	{
		FeatureVersions: []database.FeatureVersion{
			{
				Feature: database.Feature{Name: "npm"},
				Version: types.NewVersionUnsafe("1.3.10"),
			},
			{
				Feature: database.Feature{Name: "hawk"},
				Version: types.NewVersionUnsafe("4.0.1"),
			},
		},
		Data: map[string][]byte{
			"usr/lib/nodejs/npm/package.json":              feature.LoadFileForTest("npm/testdata/npm/package.json"),
			"usr/local/lib/node_modules/hawk/package.json": feature.LoadFileForTest("npm/testdata/hawk/package.json"),
		},
	},
}

func TestNpmFeaturesDetector(t *testing.T) {
	feature.TestFeaturesDetector(t, &NpmFeaturesDetector{}, npmPackagesTests)
}
