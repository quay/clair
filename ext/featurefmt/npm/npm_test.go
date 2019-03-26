// Copyright 2019 clair authors
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
	"github.com/coreos/clair/ext/featurefmt"
	"github.com/coreos/clair/ext/versionfmt/semver"
)

func TestNPMFeatureDetection(t *testing.T) {
	for _, test := range []featurefmt.TestCase{
		{
			"valid case",
			map[string]string{
				"srv/something/node_modules/react/package.json":     "npm/testdata/react.json",
				"srv/something/node_modules/react-dom/package.json": "npm/testdata/react-dom.json",
				"usr/lib/notnodejs/package.json":                    "npm/testdata/corrupt.json",
				"usr/lib/alsonotnodejs/package.json":                "npm/testdata/invalid",
				"usr/lib/notnodejs/not-a-package.json":              "npm/testdata/redux.json",
			},
			[]database.LayerFeature{
				{Feature: database.Feature{"react", "15.6.2", "semver", "source"}},
				{Feature: database.Feature{"react-dom", "15.6.2", "semver", "source"}},
			},
		},
	} {
		featurefmt.RunTest(t, test, lister{}, semver.ParserName)
	}
}
