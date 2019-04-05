// Copyright 2019
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

// Package centos implements a vulnerability source updater using the
// list of CESA from Centos Announce and the RedHat Security Data API
package centos

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"regexp"

	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/ext/versionfmt"
	"github.com/coreos/clair/ext/versionfmt/rpm"
	"github.com/coreos/clair/ext/vulnsrc"
	"github.com/coreos/clair/pkg/commonerr"
	"github.com/coreos/clair/pkg/httputil"
)

const (
	cesaURL       = "https://cefs.b-cdn.net/errata.latest.xml"
	baseURL       = "https://access.redhat.com/labs/securitydataapi/cve/"
	cveURL        = "https://access.redhat.com/labs/securitydataapi/cve.json"
	conversionURL = "https://www.redhat.com/security/data/metrics/rhsamapcpe.txt"
	updaterFlag   = "centosUpdater"
)

type updater struct{}

func init() {
	vulnsrc.RegisterUpdater("centos", &updater{})
	log.WithField("package", "CentOS").Info("initialized")
}

func (u *updater) Clean() {}

type CESA struct {
	XMLName xml.Name `xml:"opt"`
	SA      []struct {
		XMLName     xml.Name
		Description string   `xml:"description,attr"`
		From        string   `xml:"from,attr"`
		IssueDate   string   `xml:"issue_date,attr"`
		Notes       string   `xml:"notes,attr"`
		Product     string   `xml:"product,attr"`
		References  string   `xml:"references,attr"`
		Release     string   `xml:"release,attr"`
		Severity    string   `xml:"severity,attr"`
		Solution    string   `xml:"solution,attr"`
		Synopsis    string   `xml:"synopsis,attr"`
		Topic       string   `xml:"topic,attr"`
		Type        string   `xml:"type,attr"`
		OsArch      string   `xml:"os_arch"`
		OsRelease   string   `xml:"os_release"`
		Packages    []string `xml:"packages"`
	} `xml:",any"`
}

type CVES []struct {
	CVEName             string    `json:"CVE"`
	Severity            string    `json:"severity"`
	Date                time.Time `json:"public_date"`
	Advisories          []string  `json:"advisories"`
	Bugzilla            string    `json:"bugzilla"`
	BugzillaDescription string    `json:"bugzilla_description"`
	CWE                 string    `json:"CWE"`
	AffectedPackages    []string  `json:"affected_packages"`
	ResourceURL         string    `json:"resource_url"`
	Cvss3Score          float64   `json:"cvss3_score"`
}

type CVE struct {
	ThreatSeverity string `json:"threat_severity"`
	PublicDate     string `json:"public_date"`
	Bugzilla       struct {
		Description string `json:"description"`
		ID          string `json:"id"`
		URL         string `json:"url"`
	} `json:"bugzilla"`
	Cvss3 struct {
		Cvss3BaseScore     string `json:"cvss3_base_score"`
		Cvss3ScoringVector string `json:"cvss3_scoring_vector"`
		Status             string `json:"status"`
	} `json:"cvss3"`
	Cwe          string   `json:"cwe"`
	Details      []string `json:"details"`
	PackageState []struct {
		ProductName string `json:"product_name"`
		FixState    string `json:"fix_state"`
		PackageName string `json:"package_name"`
		Cpe         string `json:"cpe"`
	} `json:"package_state"`
	AffectedRelease []struct {
		ProductName string `json:"product_name"`
		ReleaseDate string `json:"release_date"`
		Advisory    string `json:"advisory"`
		Package     string `json:"package"`
		Cpe         string `json:"cpe"`
	} `json:"affected_release"`
	UpstreamFix string   `json:"upstream_fix"`
	References  []string `json:"references"`
	Name        string   `json:"name"`
}

func (u *updater) Update(datastore database.Datastore) (resp vulnsrc.UpdateResponse, err error) {
	log.WithField("package", "CentOS").Info("start fetching vulnerabilities")

	_, err = datastore.GetKeyValue(updaterFlag)
	if err != nil {
		return resp, err
	}
	rConv, err := httputil.GetWithUserAgent(conversionURL)
	if err != nil {
		log.WithError(err).Error("Could not get RHSA to CVE conversion")
		return resp, commonerr.ErrCouldNotDownload
	}
	defer rConv.Body.Close()
	if !httputil.Status2xx(rConv) {
		log.WithField("StatusCode", rConv.StatusCode).Error("Failed to download RHSA to CVE conversion db")
		return resp, commonerr.ErrCouldNotDownload
	}
	data, err := ioutil.ReadAll(rConv.Body)
	if err != nil {
		log.WithError(err).Error("could not read RHSA to CVE conversion response")
		return resp, commonerr.ErrCouldNotParse
	}
	rhsaToCve := parseConv(string(data))

	rCesa, err := httputil.GetWithUserAgent(cesaURL)
	if err != nil {
		log.WithError(err).Error("could not download CESA's errata update")
		return resp, commonerr.ErrCouldNotDownload
	}
	defer rCesa.Body.Close()
	if !httputil.Status2xx(rCesa) {
		log.WithField("StatusCode", rCesa.StatusCode).Error("Failed to update CentOS CESA db")
		return resp, commonerr.ErrCouldNotDownload
	}
	data, err = ioutil.ReadAll(rCesa.Body)
	if err != nil {
		log.WithError(err).Error("could not read CESA body")
		return resp, commonerr.ErrCouldNotParse
	}
	vCESA, _, err := parseCESA(string(data), rhsaToCve)
	if err != nil {
		return resp, err
	}
	for _, v := range vCESA {
		resp.Vulnerabilities = append(resp.Vulnerabilities, v)
	}
	log.WithField("package", "CentOS").Info("finished populating CVEs from CESA list")

	rCve, err := httputil.GetWithUserAgent(cveURL)
	if err != nil {
		log.WithError(err).Error("could not download CVEs from RH API update")
		return resp, commonerr.ErrCouldNotDownload
	}
	defer rCve.Body.Close()
	if !httputil.Status2xx(rCve) {
		log.WithField("StatusCode", rCve.StatusCode).Error("Failed to update CentOS CVE db from API")
		return resp, commonerr.ErrCouldNotDownload
	}
	data, err = ioutil.ReadAll(rCve.Body)
	if err != nil {
		log.WithError(err).Error("could not read CVE body")
		return resp, commonerr.ErrCouldNotParse
	}
	vCve, errCve := parseCVE(string(data))
	if errCve != nil {
		return resp, errCve
	}
	for _, v := range vCve {
		resp.Vulnerabilities = append(resp.Vulnerabilities, v)
	}
	log.WithField("package", "CentOS").Info("finished populating CVE vulnerabilities")

	return resp, nil
}

func parseConv(conversionData string) (rhsaToCve map[string][]string) {
	rhsaToCve = make(map[string][]string)
	rhsa := strings.Split(conversionData, "\n")
	for _, r := range rhsa {
		info := strings.Split(r, " ")
		if len(info) > 1 {
			cves := strings.Split(info[1], ",")
			rhsaToCve[info[0]] = cves
		}
	}
	return rhsaToCve
}

func parseCESA(cesaData string, rhsaToCve map[string][]string) (vulnerabilities []database.Vulnerability, addedEntries map[string]bool, err error) {
	log.WithField("package", "CentOS").Info("Parsing CESA xml")

	var cesas CESA
	addedEntries = make(map[string]bool)
	err = xml.Unmarshal([]byte(cesaData), &cesas)
	if err != nil {
		log.WithError(err).Error("could not decode CESA's XML")
		return nil, addedEntries, commonerr.ErrCouldNotParse
	}
	log.WithField("package", "CentOS").Info("Decoded CESA XML")

	for _, sa := range cesas.SA {
		// Security Advisory with at least 1 affected package, entries using CVE format
		if strings.Contains(sa.XMLName.Local, "CESA") && len(sa.Packages) > 0 && sa.Severity != "" {
			convertedNames := resolveCESAName(sa.XMLName.Local, sa.References, rhsaToCve)
			for _, name := range convertedNames {
				var vuln database.Vulnerability
				vuln.Name = name
				url := strings.Split(sa.References, " ")
				vuln.Link = url[0]
				vuln.Description = sa.Description
				vuln.Severity = convertSeverity(sa.Severity)
				addedPacks := make(map[string]bool)

				for _, pack := range sa.Packages {
					err = versionfmt.Valid(rpm.ParserName, strings.TrimSpace(pack))
					nameP, versionP := parseRPM(pack)
					if _, ok := addedPacks[nameP]; !ok {
						if err != nil {
							log.WithError(err).WithField("version", pack).Warning("could not parse package version. skipping")
						} else {
							featureVersion := database.FeatureVersion{
								Feature: database.Feature{
									Namespace: database.Namespace{
										Name:          "centos:" + sa.OsRelease,
										VersionFormat: rpm.ParserName,
									},
									Name: nameP,
								},
								Version: versionP,
							}
							vuln.FixedIn = append(vuln.FixedIn, featureVersion)
							addedPacks[nameP] = true
						}
						vulnerabilities = append(vulnerabilities, vuln)
						addedEntries[name] = true
					}
				}
			}
		}
	}
	log.WithField("package", "CentOS").Info("finished parsing CESA vulnerabilities")

	return vulnerabilities, addedEntries, nil
}

func parseCVE(cveData string) (vulnerabilities []database.Vulnerability, err error) {
	log.WithField("package", "CentOS").Info("Parsing CVES json")

	var cves CVES
	err = json.Unmarshal([]byte(cveData), &cves)
	if err != nil {
		log.WithError(err).Error("could not decode CVES json")
		return vulnerabilities, commonerr.ErrCouldNotParse
	}
	log.WithField("package", "CentOS").Info("Decoded CVES json")

	for _, cve := range cves {
		r, err := httputil.GetWithUserAgent(strings.TrimSpace(cve.ResourceURL))
		defer r.Body.Close()
		data, err := ioutil.ReadAll(r.Body)

		if err == nil || httputil.Status2xx(r) {
			var c CVE
			json.Unmarshal([]byte(data), &c)
			url := strings.Split(c.Bugzilla.URL, " ")

			var vuln database.Vulnerability
			vuln.Name = c.Name
			vuln.Link = url[0]
			vuln.Description = c.Bugzilla.Description
			vuln.Severity = convertSeverity(c.ThreatSeverity)

			if len(c.PackageState) > 0 {
				for _, pack := range c.PackageState {
					rhelPlatform, _ := regexp.Match(`red hat enterprise linux .`, []byte(strings.ToLower(pack.ProductName)))
					if rhelPlatform && (strings.ToLower(pack.FixState) != "not affected") {
						var versionP string
						switch strings.ToLower(strings.TrimSpace(pack.FixState)) {
						case "new", "affected", "will not fix":
							versionP = versionfmt.MaxVersion
						case "not affected":
							versionP = versionfmt.MinVersion
						default:
							versionP = strings.TrimSpace(pack.FixState)
						}
						featureVersion := database.FeatureVersion{
							Feature: database.Feature{
								Namespace: database.Namespace{
									Name:          "centos:" + pack.ProductName[len(pack.ProductName)-1:],
									VersionFormat: rpm.ParserName,
								},
								Name: pack.PackageName,
							},
							Version: versionP,
						}
						vuln.FixedIn = append(vuln.FixedIn, featureVersion)
					}
				}
			} else { //use c.AffectedRelease field
				for _, pack := range c.AffectedRelease {
					rhelPlatform, _ := regexp.Match(`red hat enterprise linux .`, []byte(strings.ToLower(pack.ProductName)))
					if rhelPlatform && pack.Package != "" {
						nameP, versionP := parseRPM(pack.Package)
						featureVersion := database.FeatureVersion{
							Feature: database.Feature{
								Namespace: database.Namespace{
									Name:          "centos:" + pack.ProductName[len(pack.ProductName)-1:],
									VersionFormat: rpm.ParserName,
								},
								Name: nameP,
							},
							Version: versionP,
						}
						vuln.FixedIn = append(vuln.FixedIn, featureVersion)
					}
				}
			}
			if len(vuln.FixedIn) > 0 { //assert CVE has relevant packages
				vulnerabilities = append(vulnerabilities, vuln)
			}
		} else {
			log.WithError(err).Error("could not download " + cve.CVEName + " from RH API update, skipping")
			// return resp, commonerr.ErrCouldNotDownload
			// SKIP THIS CVE
		}
	}
	log.WithField("package", "CentOS").Info("finished parsing CVE vulnerabilities")

	return
}
func convertSeverity(sev string) database.Severity {
	switch strings.ToLower(sev) {
	case "none", "n/a":
		return database.NegligibleSeverity
	case "low":
		return database.LowSeverity
	case "moderate":
		return database.MediumSeverity
	case "important", "high":
		return database.HighSeverity
	case "critical":
		return database.CriticalSeverity
	default:
		log.WithField("severity", sev).Warning("could not determine vulnerability severity")
		return database.UnknownSeverity
	}
}

func resolveCESAName(CESA string, URL string, rhsaToCve map[string][]string) (cveNames []string) {
	//convert CESA name to CVE(s) equivalent either through RHSA code or through lists.centos.org
	urls := strings.Split(URL, " ")
	RHSA := strings.Replace(CESA, "CE", "RH", 1)
	RHSA = strings.Replace(RHSA, "--", ":", 1)

	if _, ok := rhsaToCve[RHSA]; ok {
		return rhsaToCve[RHSA]
	}
	for _, u := range urls {
		if strings.Contains(u, "lists.centos.org") {
			resp, _ := httputil.GetWithUserAgent(u)
			defer resp.Body.Close()
			page, _ := ioutil.ReadAll(resp.Body)
			if strings.Contains(string(page), "CVE") {
				temp := (string(page))[strings.Index(string(page), "CVE"):]
				return []string{strings.Split(temp, " ")[0]}
			}
		}
	}

	return nil
}

func parseRPM(packInfo string) (nameP string, versionP string) {
	packInfo = strings.Replace(packInfo, ".rpm", "", 1)
	packInfo = strings.Replace(packInfo, ".centos", "", 1)
	packInfo = strings.Replace(packInfo, ".src", "", 1)
	packInfo = strings.Replace(packInfo, ".x86_64", "", 1)
	packInfo = strings.Replace(packInfo, ".i686", "", 1)
	packInfo = strings.Replace(packInfo, ".noarch", "", 1)

	re := regexp.MustCompile(`(-| )(1|2|3|4|5|6|7|8|9|0)`)
	splitIndex := re.FindStringIndex(packInfo)
	if len(splitIndex) >= 2 {
		i := splitIndex[0]
		nameP = strings.Replace(strings.ToLower(strings.TrimSpace(packInfo[:i])), " ", "-", -1)
		versionP = strings.ToLower(strings.TrimSpace(packInfo[i+1:]))
		return nameP, versionP
	}
	fmt.Println(packInfo)
	versionP = versionfmt.MaxVersion
	return packInfo, versionP
}
