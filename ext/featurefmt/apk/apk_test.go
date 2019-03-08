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
)

func TestAPKFeatureDetection(t *testing.T) {
	for _, test := range []featurefmt.TestCase{
		{
			"valid case",
			map[string]string{"lib/apk/db/installed": "apk/testdata/valid"},
			[]database.LayerFeature{
				{Feature: database.Feature{"apk-tools", "2.6.7-r0", "dpkg", "binary"}},
				{Feature: database.Feature{"musl", "1.1.14-r10", "dpkg", "binary"}},
				{Feature: database.Feature{"libssl1.0", "1.0.2h-r1", "dpkg", "binary"}},
				{Feature: database.Feature{"libc-utils", "0.7-r0", "dpkg", "binary"}},
				{Feature: database.Feature{"busybox", "1.24.2-r9", "dpkg", "binary"}},
				{Feature: database.Feature{"scanelf", "1.1.6-r0", "dpkg", "binary"}},
				{Feature: database.Feature{"alpine-keys", "1.1-r0", "dpkg", "binary"}},
				{Feature: database.Feature{"libcrypto1.0", "1.0.2h-r1", "dpkg", "binary"}},
				{Feature: database.Feature{"zlib", "1.2.8-r2", "dpkg", "binary"}},
				{Feature: database.Feature{"musl-utils", "1.1.14-r10", "dpkg", "binary"}},
				{Feature: database.Feature{"alpine-baselayout", "3.0.3-r0", "dpkg", "binary"}},
			},
		},
	} {
		featurefmt.RunTest(t, test, lister{}, dpkg.ParserName)
	}
}
