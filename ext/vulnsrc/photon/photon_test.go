package photon

import (
	"reflect"
	"sort"
	"testing"

	"github.com/quay/clair/v3/database"
	"github.com/quay/clair/v3/ext/versionfmt/dpkg"
	"github.com/stretchr/testify/assert"
)

func TestGetVersionsToBeUpdated(t *testing.T) {
	commonOldVersionToHash := map[string]string{
		"1.0": "b4a1877bbf70e861",
		"2.0": "193e3a5fc5d320d5",
		"3.0": "waddawdswawadsks",
	}
	inputOldVersionToHash := []map[string]string{
		commonOldVersionToHash,
		commonOldVersionToHash,
		commonOldVersionToHash,
		commonOldVersionToHash,
	}
	inputNewVersionToHash := []map[string]string{
		nil,
		{
			"3.0": "tttstastdasdt",
		},
		{
			"4.0": "swa1waddawdsw",
		},
		{
			"3.0": "tttstastdasdt",
			"4.0": "swa1waddawdsw",
		},
	}

	expectedOutput := [][]string{
		{},
		{
			"3.0",
		},
		{
			"4.0",
		},
		{
			"3.0",
			"4.0",
		},
	}

	for i, oldHashVersion := range inputOldVersionToHash {
		received := getVersionsToBeUpdated(oldHashVersion, inputNewVersionToHash[i])
		// received can contain the same elements as expectedOutput
		// but to be a different permutation
		sort.Strings(received)
		if !reflect.DeepEqual(expectedOutput[i], received) {
			assert.Fail(t, "The versions to be updated are not what is expected!", "Want: %v\nHave: %v \n",
				expectedOutput[i], received)
		}
	}
}

func TestCreateVulnerabilitiesReport(t *testing.T) {
	inputCVEmetadata := []cve{
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

	featuresVulnerabilityMetaData := []database.AffectedFeature{}
	for _, cveMetaData := range inputCVEmetadata {
		newAffectedFeature := database.AffectedFeature{
			FeatureType:     database.SourcePackage,
			FeatureName:     cveMetaData.Pkg,
			AffectedVersion: cveMetaData.AffectedVersion,
			FixedInVersion:  cveMetaData.ResolvedVersion,
			Namespace: database.Namespace{
				Name:          "photon:3.0",
				VersionFormat: dpkg.ParserName,
			},
		}
		featuresVulnerabilityMetaData = append(featuresVulnerabilityMetaData, newAffectedFeature)
	}
	expectedVulWithAff := []database.VulnerabilityWithAffected{
		{
			Vulnerability: database.Vulnerability{
				Name:        "CVE-2017-13078",
				Link:        "https://nvd.nist.gov/vuln/detail/CVE-2017-13078",
				Severity:    database.MediumSeverity,
				Description: "",
			},
			Affected: []database.AffectedFeature{
				featuresVulnerabilityMetaData[0],
			},
		},
		{
			Vulnerability: database.Vulnerability{
				Name:        "CVE-2019-5953",
				Link:        "https://nvd.nist.gov/vuln/detail/CVE-2019-5953",
				Severity:    database.CriticalSeverity,
				Description: "",
			},
			Affected: []database.AffectedFeature{
				featuresVulnerabilityMetaData[1],
			},
		},
	}

	received := createVulnerabilitiesReport(inputCVEmetadata, "photon:3.0")
	if !reflect.DeepEqual(expectedVulWithAff, received) {
		assert.Fail(t, "The received responce doesn't the expected database.VulnerabilityWithAffected!",
			"Want: %v\nHave: %v \n", expectedVulWithAff, received)
	}
}
