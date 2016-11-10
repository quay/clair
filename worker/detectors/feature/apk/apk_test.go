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

package apk

import (
	"testing"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/utils/types"
	"github.com/coreos/clair/worker/detectors/feature"
)

func TestAPKFeatureDetection(t *testing.T) {
	testData := []feature.TestData{
		{
			FeatureVersions: []database.FeatureVersion{
				{
					Feature: database.Feature{Name: "musl"},
					Version: types.NewVersionUnsafe("1.1.14-r10"),
				},
				{
					Feature: database.Feature{Name: "busybox"},
					Version: types.NewVersionUnsafe("1.24.2-r9"),
				},
				{
					Feature: database.Feature{Name: "alpine-baselayout"},
					Version: types.NewVersionUnsafe("3.0.3-r0"),
				},
				{
					Feature: database.Feature{Name: "alpine-keys"},
					Version: types.NewVersionUnsafe("1.1-r0"),
				},
				{
					Feature: database.Feature{Name: "zlib"},
					Version: types.NewVersionUnsafe("1.2.8-r2"),
				},
				{
					Feature: database.Feature{Name: "libcrypto1.0"},
					Version: types.NewVersionUnsafe("1.0.2h-r1"),
				},
				{
					Feature: database.Feature{Name: "libssl1.0"},
					Version: types.NewVersionUnsafe("1.0.2h-r1"),
				},
				{
					Feature: database.Feature{Name: "apk-tools"},
					Version: types.NewVersionUnsafe("2.6.7-r0"),
				},
				{
					Feature: database.Feature{Name: "scanelf"},
					Version: types.NewVersionUnsafe("1.1.6-r0"),
				},
				{
					Feature: database.Feature{Name: "musl-utils"},
					Version: types.NewVersionUnsafe("1.1.14-r10"),
				},
				{
					Feature: database.Feature{Name: "libc-utils"},
					Version: types.NewVersionUnsafe("0.7-r0"),
				},
			},
			Data: map[string][]byte{
				"lib/apk/db/installed": feature.LoadFileForTest("apk/testdata/installed"),
			},
		},
	}
	feature.TestDetector(t, &detector{}, testData)
}
