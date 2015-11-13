// Copyright 2015 quay-sec authors
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

package os

import (
	"testing"

	"github.com/coreos/quay-sec/worker/detectors"
	"github.com/stretchr/testify/assert"
)

type osTest struct {
	expectedOS      string
	expectedVersion string
	data            map[string][]byte
}

func testOSDetector(t *testing.T, detector detectors.OSDetector, tests []osTest) {
	for _, test := range tests {
		os, version := detector.Detect(test.data)
		assert.Equal(t, test.expectedOS, os)
		assert.Equal(t, test.expectedVersion, version)
	}
}
