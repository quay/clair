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
	"io/ioutil"
	"path"
	"runtime"
	"testing"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/worker/detectors"
	"github.com/stretchr/testify/assert"
)

type packagesTest struct {
	packages []database.FeatureVersion
	data     map[string][]byte
}

func loadFileForTest(name string) []byte {
	_, filename, _, _ := runtime.Caller(0)
	d, _ := ioutil.ReadFile(path.Join(path.Dir(filename)) + "/" + name)
	return d
}

func testFeaturesDetector(t *testing.T, detector detectors.FeaturesDetector, tests []packagesTest) {
	for _, test := range tests {
		packages, err := detector.Detect(test.data)
		if assert.Nil(t, err) && assert.Len(t, packages, len(test.packages)) {
			for _, expectedPkg := range test.packages {
				assert.Contains(t, packages, expectedPkg)
			}
		}
	}
}
