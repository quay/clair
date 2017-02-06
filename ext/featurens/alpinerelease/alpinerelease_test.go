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

package alpinerelease

import (
	"testing"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/ext/featurens"
	"github.com/coreos/clair/pkg/tarutil"
)

func TestDetector(t *testing.T) {
	testData := []featurens.TestData{
		{
			ExpectedNamespace: &database.Namespace{Name: "alpine:v3.3"},
			Files:             tarutil.FilesMap{"etc/alpine-release": []byte(`3.3.4`)},
		},
		{
			ExpectedNamespace: &database.Namespace{Name: "alpine:v3.4"},
			Files:             tarutil.FilesMap{"etc/alpine-release": []byte(`3.4.0`)},
		},
		{
			ExpectedNamespace: &database.Namespace{Name: "alpine:v0.3"},
			Files:             tarutil.FilesMap{"etc/alpine-release": []byte(`0.3.4`)},
		},
		{
			ExpectedNamespace: &database.Namespace{Name: "alpine:v0.3"},
			Files: tarutil.FilesMap{"etc/alpine-release": []byte(`
0.3.4
`)},
		},
		{
			ExpectedNamespace: nil,
			Files:             tarutil.FilesMap{},
		},
	}

	featurens.TestDetector(t, &detector{}, testData)
}
