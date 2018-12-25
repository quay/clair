package redhat

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/coreos/clair/database"
	RH "github.com/coreos/clair/ext/vulnsrc/redhat/redhat_npm"
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
				if vulnerability.Name == "CVE-2018-3745" {
					assert.Equal(t, "https://nvd.nist.gov/vuln/detail/CVE-2018-3745", vulnerability.Link)
					assert.Equal(t, database.MediumSeverity, vulnerability.Severity)
					assert.Equal(t, "atob 2.0.3 and earlier allocates uninitialized Buffers when number is passed in input on Node.js 4.x and below.", vulnerability.Description)

					expectedFeatures := []database.AffectedFeature{
						{
							Namespace: database.Namespace{
								Name:          "node",
								VersionFormat: "npm",
							},
							FeatureName:     "atob",
							FixedInVersion:  ">=2.1.0",
							AffectedVersion: "2.0.2",
						},
					}

					for _, expectedFeature := range expectedFeatures {
						assert.Contains(t, vulnerability.Affected, expectedFeature)
					}
				} else if vulnerability.Name == "CVE-2018-3732" {
					assert.Equal(t, "https://nvd.nist.gov/vuln/detail/CVE-2018-3732", vulnerability.Link)
					assert.Equal(t, database.MediumSeverity, vulnerability.Severity)
					assert.Equal(t, "resolve-path node module before 1.4.0 suffers from a Path Traversal vulnerability due to lack of validation of paths with certain special characters, which allows a malicious user to read content of any file with known path.", vulnerability.Description)

					expectedFeatures := []database.AffectedFeature{
						{
							Namespace: database.Namespace{
								Name:          "node",
								VersionFormat: "npm",
							},
							FeatureName:     "resolve-path",
							FixedInVersion:  ">=1.4.0",
							AffectedVersion: "1.2.0",
						},
					}

					for _, expectedFeature := range expectedFeatures {
						assert.Contains(t, vulnerability.Affected, expectedFeature)
					}
				} else if vulnerability.Name == "CVE-2018-3737" {
					assert.Equal(t, "https://nvd.nist.gov/vuln/detail/CVE-2018-3737", vulnerability.Link)
					assert.Equal(t, database.MediumSeverity, vulnerability.Severity)
					assert.Equal(t, "sshpk is vulnerable to ReDoS when parsing crafted invalid public keys.", vulnerability.Description)

					expectedFeatures := []database.AffectedFeature{
						{
							Namespace: database.Namespace{
								Name:          "node",
								VersionFormat: "npm",
							},
							FeatureName:     "sshpk",
							FixedInVersion:  ">=1.13.2",
							AffectedVersion: "1.13.1",
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
				if removecve.Name == "CVE-2018-3767" {
					assert.Equal(t, "node", removecve.Namespace)
				}
			}
		}
	}

}
