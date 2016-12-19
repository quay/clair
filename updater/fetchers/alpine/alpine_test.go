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

package alpine

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAlpine33YAMLParsing(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	path := filepath.Join(filepath.Dir(filename))

	testData, _ := os.Open(path + "/testdata/v33_main.yaml")
	defer testData.Close()

	vulns, err := parse33YAML(testData)
	if err != nil {
		assert.Nil(t, err)
	}
	assert.Equal(t, 15, len(vulns))
	assert.Equal(t, "CVE-2016-2147", vulns[0].Name)
	assert.Equal(t, "alpine:v3.3", vulns[0].FixedIn[0].Feature.Namespace.Name)
	assert.Equal(t, "busybox", vulns[0].FixedIn[0].Feature.Name)
	assert.Equal(t, "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-2147", vulns[0].Link)
}

func TestAlpine34YAMLParsing(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	path := filepath.Join(filepath.Dir(filename))

	testData, _ := os.Open(path + "/testdata/v34_main.yaml")
	defer testData.Close()

	vulns, err := parse34YAML(testData)
	if err != nil {
		assert.Nil(t, err)
	}
	assert.Equal(t, 105, len(vulns))
	assert.Equal(t, "CVE-2016-5387", vulns[0].Name)
	assert.Equal(t, "alpine:v3.4", vulns[0].FixedIn[0].Feature.Namespace.Name)
	assert.Equal(t, "apache2", vulns[0].FixedIn[0].Feature.Name)
	assert.Equal(t, "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-5387", vulns[0].Link)
}
