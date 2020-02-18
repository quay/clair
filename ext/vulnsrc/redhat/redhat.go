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

// Package redhat implements a vulnerability source updater using the
// Red Hat Vmaas API.
// https://github.com/RedHatInsights/vmaas
package redhat

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/quay/clair/v3/database"
	"github.com/quay/clair/v3/ext/versionfmt/rpm"
	"github.com/quay/clair/v3/ext/vulnsrc"
	"github.com/quay/clair/v3/pkg/commonerr"
	"github.com/quay/clair/v3/pkg/envutil"
	"github.com/quay/clair/v3/pkg/errata"
	"github.com/quay/clair/v3/pkg/httputil"
	log "github.com/sirupsen/logrus"
)

const (
	cveURL            = "https://access.redhat.com/security/cve/"
	updaterFlag       = "redHatUpdater"
	additionalAdvFlag = "vmasAdditionalAdv"
	affectedType      = database.BinaryPackage
)

var rhsaFirstTime = time.Date(2000, 1, 1, 1, 1, 1, 0, time.UTC)

// Advisory is struct for VMaaS advisory
type Advisory struct {
	Name          string    `json:"name"`
	Synopsis      string    `json:"synopsis"`
	Summary       string    `json:"summary"`
	Type          string    `json:"type"`
	Severity      string    `json:"severity"`
	Description   string    `json:"description"`
	Solution      string    `json:"solution"`
	Issued        time.Time `json:"issued"`
	Updated       time.Time `json:"updated"`
	CveList       []string  `json:"cve_list"`
	PackageList   []string  `json:"package_list"`
	BugzillaList  []string  `json:"bugzilla_list"`
	ReferenceList []string  `json:"reference_list"`
	URL           string    `json:"url"`
}

// RHSAdata is struct for VMaaS advisory response
type RHSAdata struct {
	ErrataList    map[string]Advisory `json:"errata_list"`
	Page          int                 `json:"page"`
	PageSize      int                 `json:"page_size"`
	Pages         int                 `json:"pages"`
	ModifiedSince string              `json:"modified_since"`
}

// VmaasPostRequest is struct for VMaaS post request
type VmaasPostRequest struct {
	ErrataList    []string `json:"errata_list"`
	ModifiedSince string   `json:"modified_since"`
	Page          int      `json:"page"`
}

type updater struct {
	EtClient errata.ErrataInterface
}

var vmaasURL = envutil.GetEnv("VMAAS_URL", "https://webapp-vmaas-stable.1b13.insights.openshiftapps.com/api/v1")
var errataURL = envutil.GetEnv("ERRATA_URL", "https://errata.devel.redhat.com")

func init() {
	vulnsrc.RegisterUpdater("redhat", &updater{EtClient: &errata.Errata{errataURL}})

}

func (u *updater) Update(datastore database.Datastore) (resp vulnsrc.UpdateResponse, err error) {
	log.WithField("package", "RedHat").Info("Start fetching vulnerabilities")

	// rhsaSince - last time when security data was fetched from VMaaS
	// additionalAdv - list of advisories which have been missing in CPE
	// mapping file in previous run
	lastAdvIssued, additionalAdv, err := findKeyValue(datastore)
	if err != nil {
		return resp, err
	}

	allVariants, err := u.EtClient.GetAllVariants()
	if err != nil {
		return resp, err
	}
	variantToCPEMapping := u.EtClient.VariantToCPEMapping(allVariants)

	allAdvisories, err := getAdvisories(lastAdvIssued, additionalAdv)
	if err != nil {
		return resp, err
	}
	newLastAdvIssued := lastAdvIssued
	if len(allAdvisories) > 0 {
		newLastAdvIssued = allAdvisories[0].Issued
	}
	additionalAdv = []string{}
	advisories := []Advisory{}
	for _, adv := range allAdvisories {
		if len(adv.PackageList) == 0 || len(adv.CveList) == 0 {
			log.WithField("Advisory", adv.Name).Debug("No packages or CVEs in advisory. Skipping...")
			continue
		}
		advisories = append(advisories, adv)

	}
	log.WithFields(log.Fields{
		"items":   len(advisories),
		"updater": "RedHat",
	}).Debug("Start processing advisories")
	advChan := make(chan Advisory, len(advisories))
	vulnChan := make(chan []database.VulnerabilityWithAffected, len(advisories))
	for i := 0; i < 20; i++ {
		// parallel processing
		go u.parseAdvisoryWorker(variantToCPEMapping, advChan, vulnChan)
	}

	// sort advisories to make processing faster
	sort.Slice(advisories, func(i, j int) bool {
		return len(advisories[i].PackageList)+len(advisories[i].CveList) > len(advisories[j].PackageList)+len(advisories[j].CveList)
	})
	for _, advisory := range advisories {
		advChan <- advisory
	}
	close(advChan)
	for i := 0; i < len(advisories); i++ {
		vulnerabilities := <-vulnChan
		resp.Vulnerabilities = append(resp.Vulnerabilities, vulnerabilities...)
	}
	close(vulnChan)

	log.WithFields(log.Fields{
		"items":          len(resp.Vulnerabilities),
		"updater":        "RedHat",
		"newUpdaterTime": newLastAdvIssued,
	}).Debug("Found new vulnerabilities")

	// save new timestamp to database
	resp.Flags = make(map[string]string)
	resp.Flags[updaterFlag] = newLastAdvIssued.Format(time.RFC3339)
	resp.Flags[additionalAdvFlag] = ""
	return resp, nil

}

func findKeyValue(datastore database.Datastore) (lastAdvIssued time.Time, additionalAdvSlice []string, err error) {
	// Get the timestamp from last scan
	rhsaSinceStr, ok, err := database.FindKeyValueAndRollback(datastore, updaterFlag)
	if err != nil {
		return time.Time{}, []string{}, err
	}

	if !ok {
		lastAdvIssued = rhsaFirstTime
	} else {
		lastAdvIssued, _ = time.Parse(time.RFC3339, rhsaSinceStr)
	}

	additionalAdv, ok, err := database.FindKeyValueAndRollback(datastore, additionalAdvFlag)
	if err != nil {
		return time.Time{}, []string{}, err
	}
	if additionalAdv != "" {
		additionalAdvSlice = strings.Split(additionalAdv, ",")
	}
	return lastAdvIssued, additionalAdvSlice, nil
}

func getAdvisories(lastAdvIssued time.Time, additionalAdvisories []string) (advisories []Advisory, err error) {
	// First fetch advisories which have been published since last update
	regularAdvUpdate, err := vmaasAdvisoryRequest([]string{"RHSA-.*"}, lastAdvIssued)
	if err != nil {
		return
	}
	log.WithField("items", len(regularAdvUpdate)).Debug("Found advisories in regular update.")
	var additionalUpdate []Advisory
	if len(additionalAdvisories) != 0 {
		// Now fetch advisories which have been missing in cpe mapping during previous update
		log.WithField("Advisories", additionalAdvisories).Debug("Requesting additional advisories")
		additionalUpdate, err = vmaasAdvisoryRequest(additionalAdvisories, rhsaFirstTime)
		if err != nil {
			return advisories, err
		}
		log.WithField("items", len(additionalUpdate)).Debug("Found advisories in additional update.")
	}
	allAdvNames := make(map[string]bool)
	for _, adv := range regularAdvUpdate {
		advisories = append(advisories, adv)
		allAdvNames[adv.Name] = true
	}
	for _, adv := range additionalUpdate {
		if _, ok := allAdvNames[adv.Name]; !ok {
			advisories = append(advisories, adv)
			allAdvNames[adv.Name] = true
		}
	}
	// sort advisories by issued date
	sort.Slice(advisories, func(i, j int) bool {
		return advisories[i].Issued.After(advisories[j].Issued)
	})
	return advisories, nil
}

func vmaasAdvisoryRequest(advList []string, lastAdvIssued time.Time) (advisories []Advisory, err error) {
	currentPage := 1
	for {
		// VMaaS publishes new data every N hours - adding 24 hours to query
		// should prevent advisories to be lost
		requestParams := VmaasPostRequest{
			ErrataList:    advList,
			ModifiedSince: lastAdvIssued.Add(-24 * time.Hour).Format(time.RFC3339),
			Page:          currentPage,
		}
		log.WithFields(log.Fields{
			"json": requestParams,
		}).Debug("Requesting data from VMaaS")
		// Fetch the update list.
		advisoriesURL := vmaasURL + "/errata"
		r, err := httputil.PostWithUserAgent(advisoriesURL, requestParams)
		if err != nil {
			log.WithError(err).Error("Could not download RedHat's update list")
			return advisories, commonerr.ErrCouldNotDownload
		}
		defer r.Body.Close()

		if !httputil.Status2xx(r) {
			log.WithField("StatusCode", r.StatusCode).Error("Failed to update RedHat")
			return advisories, commonerr.ErrCouldNotDownload
		}

		var rhsaData RHSAdata
		if err := json.NewDecoder(r.Body).Decode(&rhsaData); err != nil {
			return advisories, err
		}

		for advisoryName, advisory := range rhsaData.ErrataList {
			if lastAdvIssued.Before(advisory.Issued) {
				advisory.Name = advisoryName
				advisories = append(advisories, advisory)
			}
		}
		currentPage++
		if rhsaData.Page == rhsaData.Pages || rhsaData.Pages == 0 {
			// last page
			break
		}
	}
	return advisories, nil
}

func (u *updater) parseAdvisoryWorker(variantToCPEMapping map[string]string, advisory <-chan Advisory, vulnerabilities chan<- []database.VulnerabilityWithAffected) {
	for adv := range advisory {
		vuln := u.parseAdvisory(adv, variantToCPEMapping)
		vulnerabilities <- vuln
	}
}

// parseAdvisory - parse advisory metadata and create new Vulnerabilities objects
func (u *updater) parseAdvisory(advisory Advisory, variantToCPEMapping map[string]string) (vulnerabilities []database.VulnerabilityWithAffected) {
	if len(advisory.PackageList) == 0 || len(advisory.CveList) == 0 {
		// text-only advisories
		return
	}
	var advisoryPkgs map[string][]string

	advisoryPkgs, err := u.EtClient.GetAdvisoryBuildsVariants(advisory.Name)

	if err != nil {
		log.Error("Failed to fetch advisory info: " + err.Error())
		return
	}
	for _, cve := range advisory.CveList {
		packageMap := make(map[string]bool)
		vulnerability := database.VulnerabilityWithAffected{
			Vulnerability: database.Vulnerability{
				Name:        cve + " - " + advisory.Name,
				Link:        cveURL + cve,
				Severity:    severity(advisory.Severity),
				Description: advisory.Description,
			},
		}
		for _, nevra := range advisory.PackageList {
			rpmNevraObj := parseRpm(nevra)
			if rpmNevraObj.Arch != "x86_64" && rpmNevraObj.Arch != "noarch" {
				continue
			}
			var cpes []string
			for advPkg := range advisoryPkgs {
				if advPkg == (rpmNevraObj.toNVRA() + ".rpm") {
					for _, variant := range advisoryPkgs[advPkg] {
						cpe, ok := variantToCPEMapping[variant]
						if ok {
							cpes = append(cpes, cpe)
						} else {
							log.Warning(fmt.Sprintf("No CPE for: %s %s %s", variant, advPkg, advisory.Name))
						}
					}
					break
				}
			}
			if len(cpes) == 0 {
				log.Warning(fmt.Sprintf("No CPE for: %s %s", nevra, advisory.Name))
			}
			for _, cpe := range cpes {
				epochVersionRelease := rpmNevraObj.EpochVersionRelease()
				key := rpmNevraObj.Name + epochVersionRelease + cpe
				ok := packageMap[key]
				if ok {
					// filter out duplicated features (arch specific)
					continue
				}
				p := database.AffectedFeature{
					FeatureName:     rpmNevraObj.Name,
					AffectedVersion: epochVersionRelease,
					FixedInVersion:  epochVersionRelease,
					FeatureType:     affectedType,
					Namespace: database.Namespace{
						Name:          cpe,
						VersionFormat: rpm.ParserName,
					},
				}

				packageMap[key] = true
				vulnerability.Affected = append(vulnerability.Affected, p)
			}

		}
		if len(vulnerability.Affected) > 0 {
			vulnerabilities = append(vulnerabilities, vulnerability)
		}
	}
	return
}

type NEVR struct {
	Name    string
	Epoch   *int
	Version string
	Release string
}

type RPM struct {
	NEVR
	Arch string
}

type SRPM struct {
	NEVR
}

func (rpm *RPM) rpmName() string {
	return fmt.Sprintf("%s-%s-%s.%s.rpm", rpm.Name, rpm.Version, rpm.Release, rpm.Arch)
}

func parseSrpm(name string) SRPM {
	r := regexp.MustCompile(`(.*)-(([0-9]+):)?([^-]+)-([^-]+)`)
	match := r.FindStringSubmatch(name)
	srpm := SRPM{}
	srpm.Name = match[1]
	srpm.Version = match[4]
	srpm.Release = match[5]

	if match[3] != "" {
		epoch, _ := strconv.Atoi(match[3])
		srpm.Epoch = &epoch
	}
	return srpm
}

func parseRpm(name string) RPM {
	r := regexp.MustCompile(`(.*)-(([0-9]+):)?([^-]+)-([^-]+)\.([a-z0-9_]+)`)
	match := r.FindStringSubmatch(name)
	rpm := RPM{}
	rpm.Name = match[1]
	rpm.Version = match[4]
	rpm.Release = match[5]
	rpm.Arch = match[6]
	if match[3] != "" {
		epoch, _ := strconv.Atoi(match[3])
		rpm.Epoch = &epoch
	}
	return rpm
}

func (rpm *RPM) EpochVersionRelease() string {
	if rpm.Epoch != nil {
		return fmt.Sprintf("%d:%s-%s", *rpm.Epoch, rpm.Version, rpm.Release)
	}
	return fmt.Sprintf("%s-%s", rpm.Version, rpm.Release)
}

func (rpm *RPM) toNVRA() string {
	return fmt.Sprintf("%s-%s-%s.%s", rpm.Name, rpm.Version, rpm.Release, rpm.Arch)
}

func (rpm *RPM) toNVR() string {
	return fmt.Sprintf("%s-%s-%s", rpm.Name, rpm.Version, rpm.Release)
}

func (srpm *SRPM) toNVR() string {
	return fmt.Sprintf("%s-%s-%s", srpm.Name, srpm.Version, srpm.Release)
}

func severity(sev string) database.Severity {
	switch strings.Title(sev) {
	case "Low":
		return database.LowSeverity
	case "Moderate":
		return database.MediumSeverity
	case "Important":
		return database.HighSeverity
	case "Critical":
		return database.CriticalSeverity
	default:
		log.Warningf("could not determine vulnerability severity from: %s.", sev)
		return database.UnknownSeverity
	}
}

func (u *updater) Clean() {}
