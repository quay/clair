package photon

import (
	"bytes"
	"strings"

	"github.com/quay/clair/v3/database"
	"github.com/quay/clair/v3/ext/versionfmt/dpkg"
	"github.com/quay/clair/v3/ext/vulnmdsrc/nvd"
	"github.com/quay/clair/v3/ext/vulnsrc"
	"github.com/quay/clair/v3/pkg/commonerr"

	log "github.com/sirupsen/logrus"
)

const (
	cveFilesURLlprefix = "https://vmware.bintray.com/photon_cve_metadata/cve_data_photon"
	cveMetadataPrefix  = "cve_data_photon"
	cveURLprefix       = "https://nvd.nist.gov/vuln/detail/"
	updaterFlag        = "photonUpdater"
	affectedType       = database.SourcePackage
)

type cve struct {
	CVEid           string  `json:"cve_id"`
	Pkg             string  `json:"pkg"`
	CVEscore        float64 `json:"cve_score"`
	AffectedVersion string  `json:"aff_ver"`
	ResolvedVersion string  `json:"res_ver"`
}

type updater struct {
	UpdaterFlag string
	Name        string
	Namespace   string
}

func init() {
	up := &updater{}
	vulnsrc.RegisterUpdater("photon", up)
}

func (u *updater) Clean() {

}

func (u *updater) Update(datastore database.Datastore) (resp vulnsrc.UpdateResponse, err error) {
	log.WithField("package", "Photon").Info("Start fetching vulnerabilities")

	versions, err := getPhotonVersions()
	if err != nil {
		log.WithError(err).Error("Problem getting the photon versions!")
		return
	}
	// latestHash contains information for all photon versions and
	// hashes of their corresponding cve metadata files
	// they are in the format:
	// PHOTON_VERSION:HASH;PHOTON_VERSION:HASH;
	// for example: 1.0:193e3a5fc5d320d5f;2.0:b4a1877bbf70e861d386;
	latestHashes, ok, err := database.FindKeyValueAndRollback(datastore, updaterFlag)
	if err != nil {
		return
	}

	if !ok {
		latestHashes = ""
	}
	responses, err := downloadPhotonCVEfiles(versions)
	if err != nil {
		log.WithError(err).Error("Could not download photon CVE metadata files!")
		return
	}

	newCVEfilesHashes := calculateNewHashes(responses)
	oldCVEfilesHashes := extractOldHashes(latestHashes)

	versionsToBeUpdated := getVersionsToBeUpdated(oldCVEfilesHashes, newCVEfilesHashes)

	resultVuln := make([]database.VulnerabilityWithAffected, 0)
	for _, version := range versions {

		byteArr := make([]byte, 5)
		byteReader := bytes.NewReader(byteArr)
		cvesMetaData, err := parseCVEinfoJSON(byteReader)
		if err != nil {
			log.WithError(err).Error("could not unmarshal Photon OS JSON")
			return resp, err
		}

		newVulnerabilities := createVulnerabilitiesReport(cvesMetaData, version)
		resultVuln = append(resultVuln, newVulnerabilities...)
	}

	resp.Vulnerabilities = resultVuln
	resp.FlagName = updaterFlag
	resp.FlagValue = createNewUpdaterFlag(oldCVEfilesHashes, newCVEfilesHashes, versionsToBeUpdated)

	return resp, nil
}

// getVersionsToBeUpdated checks which photon versions
// have updated cve.metadata.json files
func getVersionsToBeUpdated(oldVersionToHash map[string]string, newVersionToHash map[string]string) []string {
	versionsForUpdate := make([]string, 0)
	for version, newHash := range newVersionToHash {

		if oldHash, ok := oldVersionToHash[version]; ok && oldHash == newHash {
			log.WithField("package", "Photon").Debugf("No update for photon version %v, skip", version)
		} else {
			versionsForUpdate = append(versionsForUpdate, version)
		}
	}

	return versionsForUpdate
}

// getPhotonVersions checks which photon versions have
// cve.metadata.json files to be downloaded
func getPhotonVersions() (versions []string, err error) {
	const photonVersionsURL string = "https://vmware.bintray.com/photon_cve_metadata/photon_versions.json"
	response, err := downloadFile(photonVersionsURL)
	if err != nil {
		return nil, commonerr.ErrCouldNotDownload
	}
	defer response.Body.Close()
	versions, err = parseVersions(response.Body)
	if err != nil {
		return
	}
	return
}

// createVulnerabilitiesReport creates VulnerabilityWithAffected
// slice containing metadata for the cves
func createVulnerabilitiesReport(cves []cve, photonVersion string) (vulnerabilities []database.VulnerabilityWithAffected) {
	for _, cve := range cves {
		severity := nvd.SeverityFromCVSS(cve.CVEscore)
		var vulnerability database.VulnerabilityWithAffected

		vulnerability = database.VulnerabilityWithAffected{
			Vulnerability: database.Vulnerability{
				Name:        cve.CVEid,
				Link:        strings.Join([]string{cveURLprefix, cve.CVEid}, ""),
				Severity:    severity,
				Description: "",
			},
		}
		// Create and add the feature version.
		pkg := database.AffectedFeature{
			FeatureType:     affectedType,
			FeatureName:     cve.Pkg,
			AffectedVersion: cve.AffectedVersion,
			FixedInVersion:  cve.ResolvedVersion,
			Namespace: database.Namespace{
				Name:          photonVersion,
				VersionFormat: dpkg.ParserName,
			},
		}
		vulnerability.Affected = append(vulnerability.Affected, pkg)
		vulnerabilities = append(vulnerabilities, vulnerability)
	}
	return
}
