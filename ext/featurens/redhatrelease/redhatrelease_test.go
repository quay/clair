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

package redhatrelease

import (
	"testing"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/ext/featurens"
	"github.com/coreos/clair/pkg/tarutil"
)

func TestDetector(t *testing.T) {
	testData := []featurens.TestData{
		{
			ExpectedNamespace: &database.Namespace{Name: "oracle:6"},
			Files: tarutil.FilesMap{
				"etc/oracle-release": []byte(`Oracle Linux Server release 6.8`),
			},
		},
		{
			ExpectedNamespace: &database.Namespace{Name: "oracle:7"},
			Files: tarutil.FilesMap{
				"etc/oracle-release": []byte(`Oracle Linux Server release 7.2`),
			},
		},
		{
			ExpectedNamespace: &database.Namespace{Name: "centos:6"},
			Files: tarutil.FilesMap{
				"etc/centos-release": []byte(`CentOS release 6.6 (Final)`),
			},
		},
		{
			ExpectedNamespace: &database.Namespace{Name: "centos:7"},
			Files: tarutil.FilesMap{
				"etc/system-release": []byte(`CentOS Linux release 7.1.1503 (Core)`),
			},
		},
	}

	featurens.TestDetector(t, &detector{}, testData)
}
