// Copyright 2015 clair authors
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

package utils

import (
	"bytes"
	"os"
	"path"
	"runtime"
	"testing"

	"github.com/pborman/uuid"
	"github.com/stretchr/testify/assert"
)

const fileToDownload = "http://www.google.com/robots.txt"

// TestDiff tests the diff.go source file
func TestDiff(t *testing.T) {
	cmp := CompareStringLists([]string{"a", "b", "b", "a"}, []string{"a", "c"})
	assert.Len(t, cmp, 1)
	assert.NotContains(t, cmp, "a")
	assert.Contains(t, cmp, "b")

	cmp = CompareStringListsInBoth([]string{"a", "a", "b", "c"}, []string{"a", "c", "c"})
	assert.Len(t, cmp, 2)
	assert.NotContains(t, cmp, "b")
	assert.Contains(t, cmp, "a")
	assert.Contains(t, cmp, "c")
}

// TestExec tests the exec.go source file
func TestExec(t *testing.T) {
	_, err := Exec(uuid.New(), "touch", uuid.New())
	assert.Error(t, err, "Exec should not be able to run in a not existing directory")

	o, err := Exec("/tmp", "echo", "test")
	assert.Nil(t, err, "Could not exec echo")
	assert.Equal(t, "test\n", string(o), "Could not exec echo")

	_, err = Exec("/tmp", uuid.New())
	assert.Error(t, err, "An invalid command should return an error")
}

// TestString tests the string.go file
func TestString(t *testing.T) {
	assert.False(t, Contains("", []string{}))
	assert.True(t, Contains("a", []string{"a", "b"}))
	assert.False(t, Contains("c", []string{"a", "b"}))
}

// TestTar tests the tar.go file
func TestTar(t *testing.T) {
	var err error
	var data map[string][]byte
	_, filepath, _, _ := runtime.Caller(0)
	testDataDir := "/testdata"
	for _, filename := range []string{"utils_test.tar.gz", "utils_test.tar.bz2", "utils_test.tar.xz", "utils_test.tar"} {
		testArchivePath := path.Join(path.Dir(filepath), testDataDir, filename)

		// Extract non compressed data
		data, err = SelectivelyExtractArchive(bytes.NewReader([]byte("that string does not represent a tar or tar-gzip file")), "", []string{}, 0)
		assert.Error(t, err, "Extracting non compressed data should return an error")

		// Extract an archive
		f, _ := os.Open(testArchivePath)
		defer f.Close()
		data, err = SelectivelyExtractArchive(f, "", []string{"test/"}, 0)
		assert.Nil(t, err)

		if c, n := data["test/test.txt"]; !n {
			assert.Fail(t, "test/test.txt should have been extracted")
		} else {
			assert.NotEqual(t, 0, len(c) > 0, "test/test.txt file is empty")
		}
		if _, n := data["test.txt"]; n {
			assert.Fail(t, "test.txt should not be extracted")
		}

		// File size limit
		f, _ = os.Open(testArchivePath)
		defer f.Close()
		data, err = SelectivelyExtractArchive(f, "", []string{"test"}, 50)
		assert.Equal(t, ErrExtractedFileTooBig, err)
	}
}

func TestCleanURL(t *testing.T) {
	assert.Equal(t, "Test http://test.cn/test Test", CleanURL("Test http://test.cn/test?foo=bar&bar=foo Test"))
}
