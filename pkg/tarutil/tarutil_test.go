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

package tarutil

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
)

var testTarballs = []string{
	"utils_test.tar",
	"utils_test.tar.gz",
	"utils_test.tar.bz2",
	"utils_test.tar.xz",
}

func testfilepath(filename string) string {
	_, path, _, _ := runtime.Caller(0)
	testDataDir := "/testdata"
	return filepath.Join(filepath.Dir(path), testDataDir, filename)
}

func TestExtract(t *testing.T) {
	for _, filename := range testTarballs {
		f, err := os.Open(testfilepath(filename))
		assert.Nil(t, err)
		defer f.Close()

		data, err := ExtractFiles(f, []string{"test/"})
		assert.Nil(t, err)

		if c, n := data["test/test.txt"]; !n {
			assert.Fail(t, "test/test.txt should have been extracted")
		} else {
			assert.NotEqual(t, 0, len(c) > 0, "test/test.txt file is empty")
		}
		if _, n := data["test.txt"]; n {
			assert.Fail(t, "test.txt should not be extracted")
		}
	}
}

func TestExtractUncompressedData(t *testing.T) {
	for _, filename := range testTarballs {
		f, err := os.Open(testfilepath(filename))
		assert.Nil(t, err)
		defer f.Close()

		_, err = ExtractFiles(bytes.NewReader([]byte("that string does not represent a tar or tar-gzip file")), []string{})
		assert.Error(t, err, "Extracting uncompressed data should return an error")
	}
}

func TestMaxExtractableFileSize(t *testing.T) {
	for _, filename := range testTarballs {
		f, err := os.Open(testfilepath(filename))
		assert.Nil(t, err)
		defer f.Close()
		MaxExtractableFileSize = 50
		_, err = ExtractFiles(f, []string{"test"})
		assert.Equal(t, ErrExtractedFileTooBig, err)
	}
}
