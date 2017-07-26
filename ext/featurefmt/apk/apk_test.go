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

package apk

import (
	"testing"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/ext/featurefmt"
	"github.com/coreos/clair/ext/versionfmt/dpkg"
	"github.com/coreos/clair/pkg/tarutil"
)

func TestAPKFeatureDetection(t *testing.T) {
	testFeatures := []database.Feature{
		{Name: "musl", Version: "1.1.14-r10"},
		{Name: "busybox", Version: "1.24.2-r9"},
		{Name: "alpine-baselayout", Version: "3.0.3-r0"},
		{Name: "alpine-keys", Version: "1.1-r0"},
		{Name: "zlib", Version: "1.2.8-r2"},
		{Name: "libcrypto1.0", Version: "1.0.2h-r1"},
		{Name: "libssl1.0", Version: "1.0.2h-r1"},
		{Name: "apk-tools", Version: "2.6.7-r0"},
		{Name: "scanelf", Version: "1.1.6-r0"},
		{Name: "musl-utils", Version: "1.1.14-r10"},
		{Name: "libc-utils", Version: "0.7-r0"},
	}

	for i := range testFeatures {
		testFeatures[i].VersionFormat = dpkg.ParserName
	}

	testData := []featurefmt.TestData{
		{
			Features: testFeatures,
			Files: tarutil.FilesMap{
				"lib/apk/db/installed": featurefmt.LoadFileForTest("apk/testdata/installed"),
			},
		},
	}
	featurefmt.TestLister(t, &lister{}, testData)
}
