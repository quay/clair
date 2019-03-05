// Copyright 2019 clair authors
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

package clair_test

import (
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

var headerReg = regexp.MustCompile(`^(// Copyright \d\d\d\d clair authors
//
// Licensed under the Apache License, Version 2\.0 \(the "License"\);
// you may not use this file except in compliance with the License\.
// You may obtain a copy of the License at
//
//     http://www\.apache\.org/licenses/LICENSE-2\.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied\.
// See the License for the specific language governing permissions and
// limitations under the License\.)`)

var extensions = []string{".go", ".proto"}

// even if a file's extension matches, it's skipped.
var skips = []*regexp.Regexp{
	regexp.MustCompile(`^vendor/.*`),
	regexp.MustCompile(`clair.pb.go$`),
	regexp.MustCompile(`clair.pb.gw.go$`),
}

// TestLicenseHeader ensures all Clair files have proper header.
func TestLicenseHeader(t *testing.T) {
	err := filepath.Walk(".", func(path string, fi os.FileInfo, err error) error {
		toScan := false
		for _, ext := range extensions {
			if filepath.Ext(path) == ext {
				toScan = true
				break
			}
		}

		if !toScan {
			return err
		}

		for _, skip := range skips {
			if skip.MatchString(path) {
				return err
			}
		}

		src, ioError := ioutil.ReadFile(path)
		if ioError != nil {
			panic(ioError)
		}

		if !headerReg.Match(src) {
			t.Logf("%v: license header not present", path)
			err = errors.New("missing license header")
			return err
		}

		return err
	})

	if err != nil {
		t.Fatal(err)
	}
}
