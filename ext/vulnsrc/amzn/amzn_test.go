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

package amzn

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/ext/versionfmt/rpm"
	"github.com/stretchr/testify/assert"
)

func TestAmazonLinux1(t *testing.T) {
	amazonLinux1Updater := updater{
		Name:          "Amazon Linux 2018.03",
		Namespace:     "amzn:2018.03",
		UpdaterFlag:   "amazonLinux1Updater",
		MirrorListURI: "http://repo.us-west-2.amazonaws.com/2018.03/updates/x86_64/mirror.list",
	}

	_, filename, _, _ := runtime.Caller(0)
	path := filepath.Join(filepath.Dir(filename))

	expectedDescription0Bytes, err := ioutil.ReadFile(path + "/testdata/amazon_linux_1_description_0.txt")
	expectedDescription0 := string(expectedDescription0Bytes)

	expectedDescription1Bytes, _ := ioutil.ReadFile(path + "/testdata/amazon_linux_1_description_1.txt")
	expectedDescription1 := string(expectedDescription1Bytes)

	updateInfoXml, _ := os.Open(path + "/testdata/amazon_linux_1_updateinfo.xml")
	defer updateInfoXml.Close()

	updateInfo, err := decodeUpdateInfo(updateInfoXml)
	assert.Nil(t, err)

	vulnerabilities, err := amazonLinux1Updater.alasListToVulnerabilities(updateInfo.ALASList)
	assert.Nil(t, err)

	assert.Equal(t, "ALAS-2011-1", vulnerabilities[0].Name)
	assert.Equal(t, "https://alas.aws.amazon.com/ALAS-2011-1.html", vulnerabilities[0].Link)
	assert.Equal(t, database.MediumSeverity, vulnerabilities[0].Severity)
	assert.Equal(t, expectedDescription0, vulnerabilities[0].Description)
	assert.Equal(t, 11, len(vulnerabilities[0].Affected))

	expectedFeatureVersions0 := []database.AffectedFeature{
		{
			Namespace: database.Namespace{
				Name:          "amzn:2018.03",
				VersionFormat: rpm.ParserName,
			},
			FeatureName: "httpd-devel",
			AffectedVersion: "2.2.21-1.18.amzn1",
			FixedInVersion: "2.2.21-1.18.amzn1",
			AffectedType: database.AffectBinaryPackage,
		},
		{
			Namespace: database.Namespace{
				Name:          "amzn:2018.03",
				VersionFormat: rpm.ParserName,
			},
			FeatureName: "httpd-debuginfo",
			AffectedVersion: "2.2.21-1.18.amzn1",
			FixedInVersion: "2.2.21-1.18.amzn1",
			AffectedType: database.AffectBinaryPackage,
		},
	}

	for _, expectedFeatureVersion := range expectedFeatureVersions0 {
		assert.Contains(t, vulnerabilities[0].Affected, expectedFeatureVersion)
	}

	assert.Equal(t, "ALAS-2011-2", vulnerabilities[1].Name)
	assert.Equal(t, "https://alas.aws.amazon.com/ALAS-2011-2.html", vulnerabilities[1].Link)
	assert.Equal(t, database.HighSeverity, vulnerabilities[1].Severity)
	assert.Equal(t, expectedDescription1, vulnerabilities[1].Description)
	assert.Equal(t, 8, len(vulnerabilities[1].Affected))

	expectedFeatureVersions1 := []database.AffectedFeature{
		{
			Namespace: database.Namespace{
				Name:          "amzn:2018.03",
				VersionFormat: rpm.ParserName,
			},
			FeatureName: "cyrus-imapd-debuginfo",
			AffectedVersion: "2.3.16-6.4.amzn1",
			FixedInVersion: "2.3.16-6.4.amzn1",
			AffectedType: database.AffectBinaryPackage,
		},
		{
			Namespace: database.Namespace{
				Name:          "amzn:2018.03",
				VersionFormat: rpm.ParserName,
			},
			FeatureName: "cyrus-imapd-utils",
			AffectedVersion: "2.3.16-6.4.amzn1",
			FixedInVersion: "2.3.16-6.4.amzn1",
			AffectedType: database.AffectBinaryPackage,
		},
	}

	for _, expectedFeatureVersion := range expectedFeatureVersions1 {
		assert.Contains(t, vulnerabilities[1].Affected, expectedFeatureVersion)
	}
}

func TestAmazonLinux2(t *testing.T) {
	amazonLinux2Updater := updater {
		Name:          "Amazon Linux 2",
		Namespace:     "amzn:2",
		UpdaterFlag:   "amazonLinux2Updater",
		MirrorListURI: "https://cdn.amazonlinux.com/2/core/latest/x86_64/mirror.list",
	}

	_, filename, _, _ := runtime.Caller(0)
	path := filepath.Join(filepath.Dir(filename))

	description0Bytes, _ := ioutil.ReadFile(path + "/testdata/amazon_linux_2_description_0.txt")
	expectedDescription0 := string(description0Bytes)

	description1Bytes, _ := ioutil.ReadFile(path + "/testdata/amazon_linux_2_description_1.txt")
	expectedDescription1 := string(description1Bytes)

	updateInfoXml, _ := os.Open(path + "/testdata/amazon_linux_2_updateinfo.xml")
	defer updateInfoXml.Close()

	updateInfo, err := decodeUpdateInfo(updateInfoXml)
	assert.Nil(t, err)

	vulnerabilities, err := amazonLinux2Updater.alasListToVulnerabilities(updateInfo.ALASList)
	assert.Nil(t, err)

	assert.Equal(t, "ALAS2-2018-939", vulnerabilities[0].Name)
	assert.Equal(t, "https://alas.aws.amazon.com/AL2/ALAS-2018-939.html", vulnerabilities[0].Link)
	assert.Equal(t, database.CriticalSeverity, vulnerabilities[0].Severity)
	assert.Equal(t, expectedDescription0, vulnerabilities[0].Description)
	assert.Equal(t, 13, len(vulnerabilities[0].Affected))

	expectedFeatureVersions0 := []database.AffectedFeature{
		{
			Namespace: database.Namespace{
				Name:          "amzn:2",
				VersionFormat: rpm.ParserName,
			},
			FeatureName: "kernel",
			AffectedVersion: "4.9.76-38.79.amzn2",
			FixedInVersion: "4.9.76-38.79.amzn2",
			AffectedType: database.AffectBinaryPackage,
		},
		{
			Namespace: database.Namespace{
				Name:          "amzn:2",
				VersionFormat: rpm.ParserName,
			},
			FeatureName: "kernel-headers",
			AffectedVersion: "4.9.76-38.79.amzn2",
			FixedInVersion: "4.9.76-38.79.amzn2",
			AffectedType: database.AffectBinaryPackage,
		},
	}

	for _, expectedFeatureVersion := range expectedFeatureVersions0 {
		assert.Contains(t, vulnerabilities[0].Affected, expectedFeatureVersion)
	}

	assert.Equal(t, "ALAS2-2018-942", vulnerabilities[1].Name)
	assert.Equal(t, "https://alas.aws.amazon.com/AL2/ALAS-2018-942.html", vulnerabilities[1].Link)
	assert.Equal(t, database.HighSeverity, vulnerabilities[1].Severity)
	assert.Equal(t, expectedDescription1, vulnerabilities[1].Description)
	assert.Equal(t, 5, len(vulnerabilities[1].Affected))

	expectedFeatureVersions1 := []database.AffectedFeature{
		{
			Namespace: database.Namespace{
				Name:          "amzn:2",
				VersionFormat: rpm.ParserName,
			},
			FeatureName: "qemu-kvm",
			AffectedVersion: "10:1.5.3-141.amzn2.5.3",
			FixedInVersion: "10:1.5.3-141.amzn2.5.3",
			AffectedType: database.AffectBinaryPackage,
		},
		{
			Namespace: database.Namespace{
				Name:          "amzn:2",
				VersionFormat: rpm.ParserName,
			},
			FeatureName: "qemu-img",
			AffectedVersion: "10:1.5.3-141.amzn2.5.3",
			FixedInVersion: "10:1.5.3-141.amzn2.5.3",
			AffectedType: database.AffectBinaryPackage,
		},
	}

	for _, expectedFeatureVersion := range expectedFeatureVersions1 {
		assert.Contains(t, vulnerabilities[1].Affected, expectedFeatureVersion)
	}
}
