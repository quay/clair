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

package alpinerelease

import (
	"testing"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/worker/detectors/namespace"
)

func TestAlpineReleaseNamespaceDetection(t *testing.T) {
	testData := []namespace.TestData{
		{
			ExpectedNamespace: &database.Namespace{Name: "alpine:0.3.4"},
			Data:              map[string][]byte{"/etc/alpine-release": []byte(`0.3.4`)},
		},
		{
			ExpectedNamespace: &database.Namespace{Name: "alpine:0.3.4"},
			Data: map[string][]byte{"/etc/alpine-release": []byte(`
0.3.4
`)},
		},
		{
			ExpectedNamespace: nil,
			Data:              map[string][]byte{},
		},
	}

	namespace.TestDetector(t, &detector{}, testData)
}
