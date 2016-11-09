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

// Package namespace implements utilities common to implementations of
// NamespaceDetector.
package namespace

import (
	"testing"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/worker/detectors"
	"github.com/stretchr/testify/assert"
)

// TestData represents the data used to test an implementation of
// NameSpaceDetector.
type TestData struct {
	Data              map[string][]byte
	ExpectedNamespace *database.Namespace
}

// TestDetector runs a detector on each provided instance of TestData and
// asserts the output to be equal to the expected output.
func TestDetector(t *testing.T, detector detectors.NamespaceDetector, testData []TestData) {
	for _, td := range testData {
		detectedNamespace := detector.Detect(td.Data)
		if detectedNamespace == nil {
			assert.Equal(t, td.ExpectedNamespace, detectedNamespace)
		} else {
			assert.Equal(t, td.ExpectedNamespace.Name, detectedNamespace.Name)
		}
	}
}
