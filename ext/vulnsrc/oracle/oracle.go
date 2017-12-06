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

// Package oracle implements a vulnerability source updater using the
// Oracle Linux OVAL Database.
package oracle

import (
	"bufio"
	"encoding/xml"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"

	"fmt"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/ext/versionfmt"
	"github.com/coreos/clair/ext/versionfmt/rpm"
	"github.com/coreos/clair/ext/vulnsrc"
	"github.com/coreos/clair/pkg/commonerr"
)

const (
	firstOracle5ELSA = 20070057
	ovalURI          = "https://linux.oracle.com/oval/"
	elsaFilePrefix   = "com.oracle.elsa-"
	updaterFlag      = "oracleUpdater"
)

var (
	ignoredCriterions = []string{
		" is signed with the Oracle Linux",
		".ksplice1.",
	}

	elsaRegexp = regexp.MustCompile(`com.oracle.elsa-(\d+).xml`)
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
}

type reference struct {
	Source string `xml:"source,attr"`
	URI    string `xml:"ref_url,attr"`
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
	vulnsrc.RegisterUpdater("oracle", &updater{})
}

func compareELSA(left, right int) int {
	// Fast path equals.
	if right == left {
		return 0
	}

	lstr := strconv.Itoa(left)
	rstr := strconv.Itoa(right)

	for i := range lstr {
		// If right is too short to be indexed, left is greater.
		if i >= len(rstr) {
			return 1
		}

		ldigit, _ := strconv.Atoi(string(lstr[i]))
		rdigit, _ := strconv.Atoi(string(rstr[i]))

		if ldigit > rdigit {
			return 1
		} else if ldigit < rdigit {
			return -1
		}
		continue
	}

	// Everything the length of left is the same.
	return len(lstr) - len(rstr)
}

func (u *updater) Update(datastore database.Datastore) (resp vulnsrc.UpdateResponse, err error) {
	log.WithField("package", "Oracle Linux").Info("Start fetching vulnerabilities")
	// Get the first ELSA we have to manage.
	tx, err := datastore.Begin()
	if err != nil {
		return resp, err
	}
	defer tx.Rollback()

	flagValue, ok, err := tx.FindKeyValue(updaterFlag)
	if err != nil {
		return resp, err
	}

	if !ok {
		flagValue = ""
	}

	firstELSA, err := strconv.Atoi(flagValue)
	if firstELSA == 0 || err != nil {
		firstELSA = firstOracle5ELSA
	}

	// Fetch the update list.
	r, err := http.Get(ovalURI)
	if err != nil {
		log.WithError(err).Error("could not download Oracle's update list")
		return resp, commonerr.ErrCouldNotDownload
	}
	defer r.Body.Close()

	// Get the list of ELSAs that we have to process.
	var elsaList []int
	scanner := bufio.NewScanner(r.Body)
	for scanner.Scan() {
		line := scanner.Text()
		r := elsaRegexp.FindStringSubmatch(line)
		if len(r) == 2 {
			elsaNo, _ := strconv.Atoi(r[1])
			if compareELSA(elsaNo, firstELSA) > 0 {
				elsaList = append(elsaList, elsaNo)
			}
		}
	}

	for _, elsa := range elsaList {
		// Download the ELSA's XML file.
		r, err := http.Get(ovalURI + elsaFilePrefix + strconv.Itoa(elsa) + ".xml")
		if err != nil {
			log.WithError(err).Error("could not download Oracle's update list")
			return resp, commonerr.ErrCouldNotDownload
		}

		// Parse the XML.
		vs, err := parseELSA(r.Body)
		if err != nil {
			return resp, err
		}

		// Collect vulnerabilities.
		for _, v := range vs {
			resp.Vulnerabilities = append(resp.Vulnerabilities, v)
		}
	}

	// Set the flag if we found anything.
	if len(elsaList) > 0 {
		resp.FlagName = updaterFlag
		resp.FlagValue = strconv.Itoa(largest(elsaList))
	} else {
		log.WithField("package", "Oracle Linux").Debug("no update")
	}

	return resp, nil
}

func largest(list []int) (largest int) {
	for _, element := range list {
		if element > largest {
			largest = element
		}
	}
	return
}

func (u *updater) Clean() {}

func parseELSA(ovalReader io.Reader) (vulnerabilities []database.VulnerabilityWithAffected, err error) {
	// Decode the XML.
	var ov oval
	err = xml.NewDecoder(ovalReader).Decode(&ov)
	if err != nil {
		log.WithError(err).Error("could not decode Oracle's XML")
		err = commonerr.ErrCouldNotParse
		return
	}

	// Iterate over the definitions and collect any vulnerabilities that affect
	// at least one package.
	for _, definition := range ov.Definitions {
		pkgs := toFeatures(definition.Criteria)
		if len(pkgs) > 0 {
			vulnerability := database.VulnerabilityWithAffected{
				Vulnerability: database.Vulnerability{
					Name:        name(definition),
					Link:        link(definition),
					Severity:    severity(definition),
					Description: description(definition),
				},
			}
			for _, p := range pkgs {
				vulnerability.Affected = append(vulnerability.Affected, p)
			}
			vulnerabilities = append(vulnerabilities, vulnerability)
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
	// There are duplicates in Oracle .xml files.
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
				const prefixLen = len("Oracle Linux ")
				osVersion, err = strconv.Atoi(strings.TrimSpace(c.Comment[prefixLen : prefixLen+strings.Index(c.Comment[prefixLen:], " ")]))
				if err != nil {
					log.WithError(err).WithField("comment", c.Comment).Warning("could not parse Oracle Linux release version from comment")
				}
			} else if strings.Contains(c.Comment, " is earlier than ") {
				const prefixLen = len(" is earlier than ")
				featureVersion.FeatureName = strings.TrimSpace(c.Comment[:strings.Index(c.Comment, " is earlier than ")])
				version := c.Comment[strings.Index(c.Comment, " is earlier than ")+prefixLen:]
				err := versionfmt.Valid(rpm.ParserName, version)
				if err != nil {
					log.WithError(err).WithField("version", version).Warning("could not parse package version. skipping")
				} else {
					featureVersion.AffectedVersion = version
					if version != versionfmt.MaxVersion {
						featureVersion.FixedInVersion = version
					}
				}
			}
		}

		featureVersion.Namespace.Name = "oracle" + ":" + strconv.Itoa(osVersion)
		featureVersion.Namespace.VersionFormat = rpm.ParserName

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

func name(def definition) string {
	return strings.TrimSpace(def.Title[:strings.Index(def.Title, ": ")])
}

func link(def definition) (link string) {
	for _, reference := range def.References {
		if reference.Source == "elsa" {
			link = reference.URI
			break
		}
	}

	return
}

func severity(def definition) database.Severity {
	switch strings.ToLower(def.Severity) {
	case "n/a":
		return database.NegligibleSeverity
	case "low":
		return database.LowSeverity
	case "moderate":
		return database.MediumSeverity
	case "important":
		return database.HighSeverity
	case "critical":
		return database.CriticalSeverity
	default:
		log.WithField("severity", def.Severity).Warning("could not determine vulnerability severity")
		return database.UnknownSeverity
	}
}
