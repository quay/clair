// Copyright 2017-2018 clair authors
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

package alpm

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/ext/featurefmt"
	"github.com/coreos/clair/ext/versionfmt/rpm"
	"io/ioutil"
)

func TestALPMFeatureDetection(t *testing.T) {
	testFeatures := []database.Feature{
		{Name: "bash", Version: "4.4.019-1"},
		{Name: "curl", Version: "7.59.0-2"},
		{Name: "file", Version: "5.32-1"},
		{Name: "libseccomp", Version: "2.3.2-2"},
		{Name: "zlib", Version: "1:1.2.11-2"},
	}

	for i := range testFeatures {
		testFeatures[i].VersionFormat = rpm.ParserName
	}

	files := make(map[string][]byte)
	err := filepath.Walk("testdata", func(path string, f os.FileInfo, err error) error {
		if f.Mode().IsRegular() || f.Mode()&os.ModeSymlink != 0 {
			content, err := ioutil.ReadFile(path)
			if err == nil {
				files[path] = content
			}
		}
		return nil
	})

	if err != nil {
		t.Error("could not find any files")
		return
	}

	testData := []featurefmt.TestData{
		{
			Features: testFeatures,
			Files:    files,
		},
	}
	featurefmt.TestLister(t, &lister{}, testData)
}
