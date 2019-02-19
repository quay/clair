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

// Package rhel implements a vulnerability source updater using the
// Red Hat Linux OVAL Database.
package rhel

import (
	"bufio"
	"encoding/xml"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/ext/versionfmt"
	"github.com/coreos/clair/ext/versionfmt/rpm"
	"github.com/coreos/clair/ext/vulnsrc"
	"github.com/coreos/clair/pkg/commonerr"
	"github.com/coreos/clair/pkg/httputil"
)

const (
	// Before this RHSA, it deals only with RHEL <= 4.
	firstRHEL5RHSA      = 20070044
	firstConsideredRHEL = 5

	ovalURI        = "https://www.redhat.com/security/data/oval/"
	rhsaFilePrefix = "com.redhat.rhsa-"
	updaterFlag    = "rhelUpdater"
	affectedType   = database.BinaryPackage
)

var (
	ignoredCriterions = []string{
		" is signed with Red Hat ",
		" Client is installed",
		" Workstation is installed",
		" ComputeNode is installed",
	}

	rhsaRegexp = regexp.MustCompile(`com.redhat.rhsa-(\d+).xml`)
)

type oval struct {
	Definitions []definition `xml:"definitions>definition"`
}

type definition struct {
	Title       string      `xml:"metadata>title"`
	Description string      `xml:"metadata>description"`
	References  []reference `xml:"metadata>reference"`
	Criteria    criteria    `xml:"criteria"`
	Severity    string      `xml:"metadata>advisory>severity"`
	Cves        []cve       `xml:"metadata>advisory>cve"`
}

type reference struct {
	Source string `xml:"source,attr"`
	URI    string `xml:"ref_url,attr"`
	ID     string `xml:"ref_id,attr"`
}

type cve struct {
	Impact string `xml:"impact,attr"`
	Href   string `xml:"href,attr"`
	ID     string `xml:",chardata"`
}

type criteria struct {
	Operator   string      `xml:"operator,attr"`
	Criterias  []*criteria `xml:"criteria"`
	Criterions []criterion `xml:"criterion"`
}

type criterion struct {
	Comment string `xml:"comment,attr"`
}

type updater struct{}

func init() {
	vulnsrc.RegisterUpdater("rhel", &updater{})
}

func (u *updater) Update(datastore database.Datastore) (resp vulnsrc.UpdateResponse, err error) {
	log.WithField("package", "RHEL").Info("Start fetching vulnerabilities")

	// Get the first RHSA we have to manage.
	flagValue, ok, err := database.FindKeyValueAndRollback(datastore, updaterFlag)
	if err != nil {
		return resp, err
	}

	if !ok {
		flagValue = ""
	}

	firstRHSA, err := strconv.Atoi(flagValue)
	if firstRHSA == 0 || err != nil {
		firstRHSA = firstRHEL5RHSA
	}

	// Fetch the update list.
	r, err := httputil.GetWithUserAgent(ovalURI)
	if err != nil {
		log.WithError(err).Error("could not download RHEL's update list")
		return resp, commonerr.ErrCouldNotDownload
	}
	defer r.Body.Close()

	if !httputil.Status2xx(r) {
		log.WithField("StatusCode", r.StatusCode).Error("Failed to update RHEL")
		return resp, commonerr.ErrCouldNotDownload
	}

	// Get the list of RHSAs that we have to process.
	var rhsaList []int
	scanner := bufio.NewScanner(r.Body)
	for scanner.Scan() {
		line := scanner.Text()
		r := rhsaRegexp.FindStringSubmatch(line)
		if len(r) == 2 {
			rhsaNo, _ := strconv.Atoi(r[1])
			if rhsaNo > firstRHSA {
				rhsaList = append(rhsaList, rhsaNo)
			}
		}
	}

	for _, rhsa := range rhsaList {
		// Download the RHSA's XML file.
		r, err := httputil.GetWithUserAgent(ovalURI + rhsaFilePrefix + strconv.Itoa(rhsa) + ".xml")
		if err != nil {
			log.WithError(err).Error("could not download RHEL's update list")
			return resp, commonerr.ErrCouldNotDownload
		}
		defer r.Body.Close()

		if !httputil.Status2xx(r) {
			log.WithField("StatusCode", r.StatusCode).Error("Failed to update RHEL")
			return resp, commonerr.ErrCouldNotDownload
		}

		// Parse the XML.
		vs, err := parseRHSA(r.Body)
		if err != nil {
			return resp, err
		}

		// Collect vulnerabilities.
		for _, v := range vs {
			resp.Vulnerabilities = append(resp.Vulnerabilities, v)
		}
	}

	// Set the flag if we found anything.
	if len(rhsaList) > 0 {
		resp.FlagName = updaterFlag
		resp.FlagValue = strconv.Itoa(rhsaList[len(rhsaList)-1])
	} else {
		log.WithField("package", "Red Hat").Debug("no update")
	}

	return resp, nil
}

func (u *updater) Clean() {}

func parseRHSA(ovalReader io.Reader) (vulnerabilities []database.VulnerabilityWithAffected, err error) {
	// Decode the XML.
	var ov oval
	err = xml.NewDecoder(ovalReader).Decode(&ov)
	if err != nil {
		log.WithError(err).Error("could not decode RHEL's XML")
		err = commonerr.ErrCouldNotParse
		return
	}

	// Iterate over the definitions and collect any vulnerabilities that affect
	// at least one package.
	for _, definition := range ov.Definitions {
		pkgs := toFeatures(definition.Criteria)
		if len(pkgs) > 0 {

			// Init vulnerability
			vulnerability := database.VulnerabilityWithAffected{
				Vulnerability: database.Vulnerability{
					Name:        rhsaName(definition),
					Link:        rhsaLink(definition),
					Severity:    severity(definition.Severity),
					Description: description(definition),
				},
			}
			for _, p := range pkgs {
				vulnerability.Affected = append(vulnerability.Affected, p)
			}

			// Only RHSA is present
			if len(definition.References) == 1 {
				vulnerabilities = append(vulnerabilities, vulnerability)
				continue
			}

			// Create one vulnerability by CVE
			for _, currentCve := range definition.Cves {
				vulnerability.Name = currentCve.ID
				vulnerability.Link = currentCve.Href
				if currentCve.Impact != "" && currentCve.Impact != "none" {
					vulnerability.Severity = severity(currentCve.Impact)
				} else {
					vulnerability.Severity = severity(definition.Severity)
				}
				vulnerabilities = append(vulnerabilities, vulnerability)
			}
		}
	}

	return
}

func getCriterions(node criteria) [][]criterion {
	// Filter useless criterions.
	var criterions []criterion
	for _, c := range node.Criterions {
		ignored := false

		for _, ignoredItem := range ignoredCriterions {
			if strings.Contains(c.Comment, ignoredItem) {
				ignored = true
				break
			}
		}

		if !ignored {
			criterions = append(criterions, c)
		}
	}

	if node.Operator == "AND" {
		return [][]criterion{criterions}
	} else if node.Operator == "OR" {
		var possibilities [][]criterion
		for _, c := range criterions {
			possibilities = append(possibilities, []criterion{c})
		}
		return possibilities
	}

	return [][]criterion{}
}

func getPossibilities(node criteria) [][]criterion {
	if len(node.Criterias) == 0 {
		return getCriterions(node)
	}

	var possibilitiesToCompose [][][]criterion
	for _, criteria := range node.Criterias {
		possibilitiesToCompose = append(possibilitiesToCompose, getPossibilities(*criteria))
	}
	if len(node.Criterions) > 0 {
		possibilitiesToCompose = append(possibilitiesToCompose, getCriterions(node))
	}

	var possibilities [][]criterion
	if node.Operator == "AND" {
		for _, possibility := range possibilitiesToCompose[0] {
			possibilities = append(possibilities, possibility)
		}

		for _, possibilityGroup := range possibilitiesToCompose[1:] {
			var newPossibilities [][]criterion

			for _, possibility := range possibilities {
				for _, possibilityInGroup := range possibilityGroup {
					var p []criterion
					p = append(p, possibility...)
					p = append(p, possibilityInGroup...)
					newPossibilities = append(newPossibilities, p)
				}
			}

			possibilities = newPossibilities
		}
	} else if node.Operator == "OR" {
		for _, possibilityGroup := range possibilitiesToCompose {
			for _, possibility := range possibilityGroup {
				possibilities = append(possibilities, possibility)
			}
		}
	}

	return possibilities
}

func toFeatures(criteria criteria) []database.AffectedFeature {
	// There are duplicates in Red Hat .xml files.
	// This map is for deduplication.
	featureVersionParameters := make(map[string]database.AffectedFeature)

	possibilities := getPossibilities(criteria)
	for _, criterions := range possibilities {
		var (
			featureVersion database.AffectedFeature
			osVersion      int
			err            error
		)

		// Attempt to parse package data from trees of criterions.
		for _, c := range criterions {
			if strings.Contains(c.Comment, " is installed") {
				const prefixLen = len("Red Hat Enterprise Linux ")
				osVersion, err = strconv.Atoi(strings.TrimSpace(c.Comment[prefixLen : prefixLen+strings.Index(c.Comment[prefixLen:], " ")]))
				if err != nil {
					log.WithField("criterion comment", c.Comment).Warning("could not parse Red Hat release version from criterion comment")
				}
			} else if strings.Contains(c.Comment, " is earlier than ") {
				const prefixLen = len(" is earlier than ")
				featureVersion.FeatureName = strings.TrimSpace(c.Comment[:strings.Index(c.Comment, " is earlier than ")])
				featureVersion.FeatureType = affectedType
				version := c.Comment[strings.Index(c.Comment, " is earlier than ")+prefixLen:]
				err := versionfmt.Valid(rpm.ParserName, version)
				if err != nil {
					log.WithError(err).WithField("version", version).Warning("could not parse package version. skipping")
				} else {
					featureVersion.AffectedVersion = version
					if version != versionfmt.MaxVersion {
						featureVersion.FixedInVersion = version
					}
					featureVersion.Namespace.VersionFormat = rpm.ParserName
				}
			}
		}

		if osVersion >= firstConsideredRHEL {
			// TODO(vbatts) this is where features need multiple labels ('centos' and 'rhel')
			featureVersion.Namespace.Name = "centos" + ":" + strconv.Itoa(osVersion)
		} else {
			continue
		}

		if featureVersion.Namespace.Name != "" && featureVersion.FeatureName != "" && featureVersion.AffectedVersion != "" && featureVersion.FixedInVersion != "" {
			featureVersionParameters[featureVersion.Namespace.Name+":"+featureVersion.FeatureName] = featureVersion
		} else {
			log.WithField("criterions", fmt.Sprintf("%v", criterions)).Warning("could not determine a valid package from criterions")
		}
	}

	// Convert the map to slice.
	var featureVersionParametersArray []database.AffectedFeature
	for _, fv := range featureVersionParameters {
		featureVersionParametersArray = append(featureVersionParametersArray, fv)
	}

	return featureVersionParametersArray
}

func description(def definition) (desc string) {
	// It is much more faster to proceed like this than using a Replacer.
	desc = strings.Replace(def.Description, "\n\n\n", " ", -1)
	desc = strings.Replace(desc, "\n\n", " ", -1)
	desc = strings.Replace(desc, "\n", " ", -1)
	return
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

func rhsaName(def definition) string {
	return strings.TrimSpace(def.Title[:strings.Index(def.Title, ": ")])
}

func rhsaLink(def definition) (link string) {
	if len(def.References) > 0 {
		link = def.References[0].URI
	}
	return
}
