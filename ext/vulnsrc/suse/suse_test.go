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

package suse

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/ext/versionfmt/rpm"
	"github.com/stretchr/testify/assert"
)

func TestOpenSUSEParser(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	path := filepath.Join(filepath.Dir(filename))

	// Test parsing testdata/fetcher_opensuse_test.1.xml
	testFile, _ := os.Open(path + "/testdata/fetcher_opensuse_test.1.xml")
	defer testFile.Close()

	u := newUpdater(OpenSUSE)
	osVersion := "42.3"

	vulnerabilities, generationTime, err := parseOval(testFile, u.NamespaceName, osVersion)
	assert.Nil(t, err)
	assert.Equal(t, int64(1467000286), generationTime)

	if assert.Nil(t, err) && assert.Len(t, vulnerabilities, 1) {
		assert.Equal(t, "CVE-2012-2150", vulnerabilities[0].Name)
		assert.Equal(t, "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-2150", vulnerabilities[0].Link)
		assert.Equal(t, `xfs_metadump in xfsprogs before 3.2.4 does not properly obfuscate file data, which allows remote attackers to obtain sensitive information by reading a generated image.`, vulnerabilities[0].Description)

		expectedFeatures := []database.AffectedFeature{
			{
				Namespace: database.Namespace{
					Name:          fmt.Sprintf("%s:%s", u.NamespaceName, osVersion),
					VersionFormat: rpm.ParserName,
				},
				FeatureName:     "xfsprogs",
				FixedInVersion:  "3.2.1-5.1",
				AffectedVersion: "3.2.1-5.1",
			},
			{
				Namespace: database.Namespace{
					Name:          fmt.Sprintf("%s:%s", u.NamespaceName, osVersion),
					VersionFormat: rpm.ParserName,
				},
				FeatureName:     "xfsprogs-devel",
				FixedInVersion:  "3.2.1-5.1",
				AffectedVersion: "3.2.1-5.1",
			},
		}

		for _, expectedFeature := range expectedFeatures {
			assert.Contains(t, vulnerabilities[0].Affected, expectedFeature)
		}
	}

}

func TestSUSEParser(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	path := filepath.Join(filepath.Dir(filename))

	// Test parsing testdata/fetcher_opensuse_test.1.xml
	testFile, _ := os.Open(path + "/testdata/fetcher_sle_test.1.xml")
	defer testFile.Close()

	u := newUpdater(SUSE)
	osVersion := "12"

	vulnerabilities, generationTime, err := parseOval(testFile, u.NamespaceName, osVersion)
	assert.Nil(t, err)
	assert.Equal(t, int64(1467000286), generationTime)

	if assert.Nil(t, err) && assert.Len(t, vulnerabilities, 1) {
		assert.Equal(t, "CVE-2012-2150", vulnerabilities[0].Name)
		assert.Equal(t, "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-2150", vulnerabilities[0].Link)
		assert.Equal(t, `xfs_metadump in xfsprogs before 3.2.4 does not properly obfuscate file data, which allows remote attackers to obtain sensitive information by reading a generated image.`, vulnerabilities[0].Description)

		expectedFeatures := []database.AffectedFeature{
			{
				Namespace: database.Namespace{
					Name:          fmt.Sprintf("%s:%s", u.NamespaceName, osVersion),
					VersionFormat: rpm.ParserName,
				},
				FeatureName:     "xfsprogs",
				FixedInVersion:  "3.2.1-3.5",
				AffectedVersion: "3.2.1-3.5",
			},
			{
				Namespace: database.Namespace{
					Name:          "sles:12.1",
					VersionFormat: rpm.ParserName,
				},
				FeatureName:     "xfsprogs",
				FixedInVersion:  "3.2.1-3.5",
				AffectedVersion: "3.2.1-3.5",
			},
		}

		for _, expectedFeature := range expectedFeatures {
			assert.Contains(t, vulnerabilities[0].Affected, expectedFeature)
		}
	}
}

func TestPkgInstalledCommentRegexp(t *testing.T) {
	testData := map[string][]string{
		"krb5-1.12.1-19.1 is installed":                               {"krb5", "1.12.1-19.1"},
		"krb5-32bit-1.12.1-19.1 is installed":                         {"krb5-32bit", "1.12.1-19.1"},
		"krb5-client-1.12.1-19.1 is installed":                        {"krb5-client", "1.12.1-19.1"},
		"krb5-plugin-kdb-ldap-1.12.1-19.1 is installed":               {"krb5-plugin-kdb-ldap", "1.12.1-19.1"},
		"sysvinit-tools-2.88+-96.1 is installed":                      {"sysvinit-tools", "2.88+-96.1"},
		"ntp-4.2.8p10-63.3 is installed":                              {"ntp", "4.2.8p10-63.3"},
		"libid3tag0-0.15.1b-182.58 is installed":                      {"libid3tag0", "0.15.1b-182.58"},
		"libopenssl-devel-1.0.2j-55.1 is installed":                   {"libopenssl-devel", "1.0.2j-55.1"},
		"libMagickCore-6_Q16-1-6.8.8.1-5.8 is installed":              {"libMagickCore-6_Q16-1", "6.8.8.1-5.8"},
		"libGraphicsMagick++-Q16-12-1.3.25-11.44.1 is installed":      {"libGraphicsMagick++-Q16-12", "1.3.25-11.44.1"},
		"freerdp-2.0.0~git.1463131968.4e66df7-11.69 is installed":     {"freerdp", "2.0.0~git.1463131968.4e66df7-11.69"},
		"libfreerdp2-2.0.0~git.1463131968.4e66df7-11.69 is installed": {"libfreerdp2", "2.0.0~git.1463131968.4e66df7-11.69"},
		"ruby2.1-rubygem-sle2docker-0.2.3-5.1 is installed":           {"ruby2.1-rubygem-sle2docker", "0.2.3-5.1"},
		"xen-libs-4.4.1_06-2.2 is installed":                          {"xen-libs", "4.4.1_06-2.2"},
		"runc-0.1.1+gitr2816_02f8fa7 is installed":                    {"runc", "0.1.1+gitr2816_02f8fa7"},
	}

	for pkg, expectations := range testData {
		name, version, err := splitPackageNameAndVersion(pkg[:len(pkg)-len(" is installed")])
		assert.Nil(t, err)
		assert.Equal(t, expectations[0], name)
		assert.Equal(t, expectations[1], version)
	}

	name, version, err := splitPackageNameAndVersion("invalid-package is installed")
	assert.NotNil(t, err)
	assert.Empty(t, name)
	assert.Empty(t, version)
}
