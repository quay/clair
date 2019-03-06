// Copyright 2018 clair authors
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

// Package featurefmt contains utility functions for featurefmt tests
package featurefmt

import (
	"io/ioutil"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/pkg/tarutil"
)

// LoadFileForTest can be used in order to obtain the []byte contents of a file
// that is meant to be used for test data.
func LoadFileForTest(name string) []byte {
	_, filename, _, _ := runtime.Caller(0)
	path := filepath.Join(filepath.Dir(filename), name)
	d, err := ioutil.ReadFile(path)
	if err != nil {
		panic(err)
	}

	return d
}

func loadTestFiles(testFilePaths map[string]string) tarutil.FilesMap {
	m := tarutil.FilesMap{}
	for tarPath, fsPath := range testFilePaths {
		m[tarPath] = LoadFileForTest(fsPath)
	}

	return m
}

// TestCase is used by the RunTest function to execute.
type TestCase struct {
	Name           string
	FilePaths      map[string]string
	ExpectedResult []database.LayerFeature
}

// RunTest runs a featurefmt test by loading the package info database files and
// the expected packages.
func RunTest(t *testing.T, test TestCase, lister Lister, expectedVersionFormat string) {
	t.Run(test.Name, func(t *testing.T) {
		filesMap := loadTestFiles(test.FilePaths)
		expected := test.ExpectedResult
		features, err := lister.ListFeatures(filesMap)
		require.Nil(t, err)
		visited := map[database.LayerFeature]bool{}
		// we only enforce the unique packages to match, the result features
		// should be always deduplicated.
		for _, pkg := range expected {
			visited[pkg] = false
		}

		assert.Len(t, features, len(visited))
		for _, f := range features {
			assert.Equal(t, expectedVersionFormat, f.VersionFormat)
			if ok, found := visited[f]; ok {
				assert.Fail(t, "duplicated features is not allowed", "feature=%#v", f)
			} else if !found {
				assert.Fail(t, "unexpected feature", "feature = %#v", f)
			}

			visited[f] = true
		}

		missingPackages := []database.LayerFeature{}
		for pkg, ok := range visited {
			if !ok {
				missingPackages = append(missingPackages, pkg)
			}
		}

		assert.Len(t, missingPackages, 0, "missing packages")
	})
}
