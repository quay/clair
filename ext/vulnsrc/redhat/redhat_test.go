package redhat

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/coreos/clair/database"
	RH "github.com/coreos/clair/ext/vulnsrc/redhat/redhat_maven"
	"github.com/stretchr/testify/assert"
)

func TestRedhatParsing(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	path := filepath.Join(filepath.Dir(filename))

	testData, err := os.Open(path + "/testdata/redhat_test.json")
	bytes, err := ioutil.ReadAll(testData)
	defer testData.Close()

	vulnerabilities, removeCve, err := RH.ParseRedhatJSON(bytes)
	if assert.Nil(t, err) {
		if assert.Len(t, vulnerabilities, 3) {
			for _, vulnerability := range vulnerabilities {
				if vulnerability.Name == "CVE-2013-4310" {
					assert.Equal(t, "https://nvd.nist.gov/vuln/detail/CVE-2013-4310", vulnerability.Link)
					assert.Equal(t, database.MediumSeverity, vulnerability.Severity)
					assert.Equal(t, "The Struts 2 action mapping mechanism supports the special parameter prefix  action: which is intended to help with attaching navigational information to  buttons within forms", vulnerability.Description)

					expectedFeatures := []database.AffectedFeature{
						{
							Namespace: database.Namespace{
								Name:          "java",
								VersionFormat: "maven",
							},
							FeatureName:     "org.apache.struts:struts2-core",
							FixedInVersion:  ">=2.3.15.3,2.3.15",
							AffectedVersion: "2.3.8",
						},
					}

					for _, expectedFeature := range expectedFeatures {
						assert.Contains(t, vulnerability.Affected, expectedFeature)
					}
				} else if vulnerability.Name == "CVE-2015-5377" {
					assert.Equal(t, "https://nvd.nist.gov/vuln/detail/CVE-2015-5377", vulnerability.Link)
					assert.Equal(t, database.HighSeverity, vulnerability.Severity)
					assert.Equal(t, "Some description here updated just now.", vulnerability.Description)

					expectedFeatures := []database.AffectedFeature{
						{
							Namespace: database.Namespace{
								Name:          "java",
								VersionFormat: "maven",
							},
							FeatureName:     "org.elasticsearch:elasticsearch",
							FixedInVersion:  "",
							AffectedVersion: "1.6.0",
						},
					}

					for _, expectedFeature := range expectedFeatures {
						assert.Contains(t, vulnerability.Affected, expectedFeature)
					}
				} else if vulnerability.Name == "CVE-2013-4366" {
					assert.Equal(t, "https://nvd.nist.gov/vuln/detail/CVE-2013-4366", vulnerability.Link)
					assert.Equal(t, database.HighSeverity, vulnerability.Severity)
					assert.Equal(t, "some desc", vulnerability.Description)

					expectedFeatures := []database.AffectedFeature{
						{
							Namespace: database.Namespace{
								Name:          "java",
								VersionFormat: "maven",
							},
							FeatureName:     "httpclient",
							FixedInVersion:  "4.3.1",
							AffectedVersion: "4.3",
						},
					}

					for _, expectedFeature := range expectedFeatures {
						assert.Contains(t, vulnerability.Affected, expectedFeature)
					}
				} else {
					assert.Fail(t, "Wrong vulnerability name: ", vulnerability.Namespace.Name+":"+vulnerability.Name)
				}
			}
		}
		if assert.Len(t, removeCve, 1) {
			for _, removecve := range removeCve {
				if removecve.Name == "CVE-2016-2141" {
					assert.Equal(t, "java", removecve.Namespace)
				}
			}
		}
	}

}
