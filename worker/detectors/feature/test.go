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

// Package feature implements utilities common to implementations of
// FeatureDetector.
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

// TestData represents the data used to test an implementation of
// FeatureDetector.
type TestData struct {
	Data            map[string][]byte
	FeatureVersions []database.FeatureVersion
}

// LoadFileForTest can be used in order to obtain the []byte contents of a file
// that is meant to be used for test data.
func LoadFileForTest(name string) []byte {
	_, filename, _, _ := runtime.Caller(0)
	d, _ := ioutil.ReadFile(filepath.Join(filepath.Dir(filename)) + "/" + name)
	return d
}

// TestDetector runs a detector on each provided instance of TestData and
// asserts the ouput to be equal to the expected output.
func TestDetector(t *testing.T, detector detectors.FeaturesDetector, testData []TestData) {
	for _, td := range testData {
		featureVersions, err := detector.Detect(td.Data)
		if assert.Nil(t, err) && assert.Len(t, featureVersions, len(td.FeatureVersions)) {
			for _, expectedFeatureVersion := range td.FeatureVersions {
				assert.Contains(t, featureVersions, expectedFeatureVersion)
			}
		}
	}
}
