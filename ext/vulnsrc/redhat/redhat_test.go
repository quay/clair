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

package redhat

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/ext/versionfmt/rpm"
	"github.com/stretchr/testify/assert"
)

func TestRHELParserOneCVE(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	path := filepath.Join(filepath.Dir(filename))

	// Test parsing testdata/advisory.json
	testFile, _ := os.Open(filepath.Join(path, "/testdata/advisory.json"))
	var rhsaData RHSAdata
	if err := json.NewDecoder(testFile).Decode(&rhsaData); err != nil {
		panic(err)
	}
	vulnerabilities := parseAdvisory(rhsaData.ErrataList["RHSA-2019:0139"])
	assert.Equal(t, "CVE-2017-2582", vulnerabilities[0].Name)
	assert.Equal(t, "https://access.redhat.com/security/cve/CVE-2017-2582", vulnerabilities[0].Link)
	assert.Equal(t, database.MediumSeverity, vulnerabilities[0].Severity)
	assert.Equal(t, "Red Hat JBoss Enterprise Application Platform is a platform for Java applications based on the JBoss Application Server.\n\nThis release serves as a replacement for Red Hat JBoss Enterprise Application Platform 7.1, and includes bug fixes and enhancements. Refer to the Red Hat JBoss Enterprise Application Platform 7.2.0 Release Notes for information on the most significant bug fixes and enhancements included in this release.\n\nSecurity Fix(es):\n\n* picketlink: SAML request parser replaces special strings with system properties (CVE-2017-2582)\n\nFor more details about the security issue(s), including the impact, a CVSS\nscore, and other related information, refer to the CVE page(s) listed in\nthe References section.\n\nThe CVE-2017-2582 issue was discovered by Hynek Mlnarik (Red Hat).", vulnerabilities[0].Description)

	expectedFeatures := []database.AffectedFeature{
		{
			AffectedType: affectedType,
			Namespace: database.Namespace{
				Name:          "redhat",
				VersionFormat: rpm.ParserName,
			},
			FeatureName:     "tomcat7-docs-webapp",
			AffectedVersion: "7.0.70-31.ep7.el6",
			FixedInVersion:  "7.0.70-31.ep7.el6",
		},
		{
			AffectedType: affectedType,
			Namespace: database.Namespace{
				Name:          "redhat",
				VersionFormat: rpm.ParserName,
			},
			FeatureName:     "tomcat7-selinux",
			AffectedVersion: "7.0.70-31.ep7.el6",
			FixedInVersion:  "7.0.70-31.ep7.el6",
		},
	}

	for _, expectedFeature := range expectedFeatures {
		assert.Contains(t, vulnerabilities[0].Affected, expectedFeature)
	}
}
