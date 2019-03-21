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

package python_egg

import (
	"testing"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/ext/featurefmt"
	"github.com/coreos/clair/ext/versionfmt/pep440"
)

func TestPythonEggFeatureDetection(t *testing.T) {
	for _, test := range []featurefmt.TestCase{
		{
			"valid case",
			map[string]string{
				"usr/lib/python/site-packages/foo.egg-info/PKG-INFO": "python_egg/testdata/pkginfo.txt",
				"usr/lib/python/site-packages/bar.egg-info/PKG-INFO": "python_egg/testdata/invalid.txt",
				"usr/lib/python/site-packages/baz.egg-info/PKG-INFO": "python_egg/testdata/missing-name.txt",
			},
			[]database.LayerFeature{
				{Feature: database.Feature{"enum34", "1.1.6", "pep440", "source"}},
			},
		},
	} {
		featurefmt.RunTest(t, test, lister{}, pep440.ParserName)
	}
}
