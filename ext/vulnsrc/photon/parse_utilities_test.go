package photon

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseCVEinfoJSON(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	testFile, _ := os.Open(filepath.Join(filepath.Dir(filename), "/testdata/cve_metadata.json"))

	expectedCVEmetadata := []cve{
		{
			CVEid:           "CVE-2017-13078",
			Pkg:             "wpa_supplicant",
			CVEscore:        5.3,
			AffectedVersion: "all versions before 2.7-1.ph3 are vulnerable",
			ResolvedVersion: "2.7-1.ph3",
		},
		{
			CVEid:           "CVE-2019-5953",
			Pkg:             "wget",
			CVEscore:        9.8,
			AffectedVersion: "all versions before 1.20.3-1.ph3 are vulnerable",
			ResolvedVersion: "1.20.3-1.ph3",
		},
	}

	receivedCVEsMetaData, err := parseCVEinfoJSON(testFile)
	if err != nil {
		assert.Fail(t, "Parsing JSON test failed!", err)
	}
	if !reflect.DeepEqual(expectedCVEmetadata, receivedCVEsMetaData) {
		assert.Fail(t, "The receivedCVEmetadata is not what is expected!", "Want: %v \n Have: %v \n",
			expectedCVEmetadata, receivedCVEsMetaData)
	}
}

func TestParseVersions(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	testFile, _ := os.Open(filepath.Join(filepath.Dir(filename), "/testdata/photon_versions.json"))
	expectedVersions := []string{"1.0", "2.0", "3.0"}
	receivedVersions, err := parseVersions(testFile)
	if err != nil {
		assert.Fail(t, "Parsing photon version file test failed!", err)
	}

	if !reflect.DeepEqual(expectedVersions, receivedVersions) {
		assert.Fail(t, "The responce doesn't contain an expected element!", "Want: %v \nHave: %v \n",
			expectedVersions, receivedVersions)
	}
}
