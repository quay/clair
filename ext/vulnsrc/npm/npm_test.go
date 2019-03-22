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

package npm

import (
	"github.com/coreos/clair/database"
	"github.com/coreos/clair/ext/versionfmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"path/filepath"
	"runtime"
	"testing"
)

func TestVulnParsing(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	vulns, err := parseNpmVulns(filepath.Join(filepath.Dir(filename), "testdata"))
	require.Nil(t, err)

	assert.Equal(t, 2, len(vulns))

	assert.Equal(t, "NSWG-ECO-477", vulns[0].Name)
	assert.Equal(t, "npm", vulns[0].Namespace.Name)

	assert.Equal(t, "flatmap-stream malicious package (distributed via the popular events-stream)", vulns[0].Description)
	assert.Equal(t, "https://github.com/nodejs/security-wg/blob/master/vuln/npm/477.json", vulns[0].Link)
	assert.Equal(t, database.CriticalSeverity, vulns[0].Severity)

	assert.Equal(t, database.SourcePackage, vulns[0].Affected[0].FeatureType)
	assert.Equal(t, "npm", vulns[0].Affected[0].Namespace.Name)
	assert.Equal(t, "flatmap-stream", vulns[0].Affected[0].FeatureName)
	assert.Equal(t, "*", vulns[0].Affected[0].AffectedVersion)
	assert.Equal(t, versionfmt.MaxVersion, vulns[0].Affected[0].FixedInVersion)

	// ensure vulnerabilities with CVEs get correctly mapped
	assert.Equal(t, "CVE-2016-3956", vulns[1].Name)
	assert.Equal(t, database.MediumSeverity, vulns[1].Severity)
	assert.Equal(t, ">= 2.15.1 <= 3.0.0 || >= 3.8.3", vulns[1].Affected[0].FixedInVersion)
}
