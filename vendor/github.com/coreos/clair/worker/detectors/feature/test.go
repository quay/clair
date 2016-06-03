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

package feature

import (
	"io/ioutil"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/worker/detectors"
	"github.com/stretchr/testify/assert"
)

type FeatureVersionTest struct {
	FeatureVersions []database.FeatureVersion
	Data            map[string][]byte
}

func LoadFileForTest(name string) []byte {
	_, filename, _, _ := runtime.Caller(0)
	d, _ := ioutil.ReadFile(filepath.Join(filepath.Dir(filename)) + "/" + name)
	return d
}

func TestFeaturesDetector(t *testing.T, detector detectors.FeaturesDetector, tests []FeatureVersionTest) {
	for _, test := range tests {
		featureVersions, err := detector.Detect(test.Data)
		if assert.Nil(t, err) && assert.Len(t, featureVersions, len(test.FeatureVersions)) {
			for _, expectedFeatureVersion := range test.FeatureVersions {
				assert.Contains(t, featureVersions, expectedFeatureVersion)
			}
		}
	}
}
