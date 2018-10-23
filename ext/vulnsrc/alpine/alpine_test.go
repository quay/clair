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
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestYAMLParsing(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	path := filepath.Join(filepath.Dir(filename))
	secdb, err := newSecDB(filepath.Join(path, "/testdata/v34_main.yaml"))
	require.Nil(t, err)
	vulns := secdb.Vulnerabilities()

	assert.Equal(t, 105, len(vulns))
	assert.Equal(t, "CVE-2016-5387", vulns[0].Name)
	assert.Equal(t, "alpine:v3.4", vulns[0].Namespace.Name)
	assert.Equal(t, "apache2", vulns[0].Affected[0].FeatureName)
	assert.Equal(t, "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-5387", vulns[0].Link)
}
