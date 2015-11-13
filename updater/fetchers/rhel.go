// Copyright 2015 quay-sec authors
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

package fetchers

import (
	"bufio"
	"encoding/xml"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/coreos/quay-sec/database"
	cerrors "github.com/coreos/quay-sec/utils/errors"
	"github.com/coreos/quay-sec/updater"
	"github.com/coreos/quay-sec/utils/types"
)

const (
	// Before this RHSA, it deals only with RHEL <= 4.
	firstRHEL5RHSA      = 20070044
	firstConsideredRHEL = 5

	ovalURI         = "https://www.redhat.com/security/data/oval/"
	rhsaFilePrefix  = "com.redhat.rhsa-"
	rhelUpdaterFlag = "rhelUpdater"
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

// RHELFetcher implements updater.Fetcher and gets vulnerability updates from
// the Red Hat OVAL definitions.
type RHELFetcher struct{}

func init() {
	updater.RegisterFetcher("Red Hat", &RHELFetcher{})
}

// FetchUpdate gets vulnerability updates from the Red Hat OVAL definitions.
func (f *RHELFetcher) FetchUpdate() (resp updater.FetcherResponse, err error) {
	log.Info("fetching Red Hat vulneratibilities")

	// Get the first RHSA we have to manage.
	flagValue, err := database.GetFlagValue(rhelUpdaterFlag)
	if err != nil {
		return resp, err
	}
	firstRHSA, err := strconv.Atoi(flagValue)
	if firstRHSA == 0 || err != nil {
		firstRHSA = firstRHEL5RHSA
	}

	// Fetch the update list.
	r, err := http.Get(ovalURI)
	if err != nil {
		log.Errorf("could not download RHEL's update list: %s", err)
		return resp, cerrors.ErrCouldNotDownload
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
		r, err := http.Get(ovalURI + rhsaFilePrefix + strconv.Itoa(rhsa) + ".xml")
		if err != nil {
			log.Errorf("could not download RHEL's update file: %s", err)
			return resp, cerrors.ErrCouldNotDownload
		}

		// Parse the XML.
		vs, err := parseRHSA(r.Body)
		if err != nil {
			return resp, err
		}

		// Collect vulnerabilities.
		for _, v := range vs {
			if len(v.FixedIn) > 0 {
				resp.Vulnerabilities = append(resp.Vulnerabilities, v)
			}
		}
	}

	// Set the flag if we found anything.
	if len(rhsaList) > 0 {
		resp.FlagName = rhelUpdaterFlag
		resp.FlagValue = strconv.Itoa(rhsaList[len(rhsaList)-1])
	} else {
		log.Debug("no Red Hat update.")
	}

	return resp, nil
}

func parseRHSA(ovalReader io.Reader) (vulnerabilities []updater.FetcherVulnerability, err error) {
	// Decode the XML.
	var ov oval
	err = xml.NewDecoder(ovalReader).Decode(&ov)
	if err != nil {
		log.Errorf("could not decode RHEL's XML: %s.", err)
		err = ErrCouldNotParse
		return
	}

	// Iterate over the definitions and collect any vulnerabilities that affect
	// more than one package.
	for _, definition := range ov.Definitions {
		packages := toPackages(definition.Criteria)
		if len(packages) > 0 {
			vuln := updater.FetcherVulnerability{
				ID:          name(definition),
				Link:        link(definition),
				Priority:    priority(definition),
				Description: description(definition),
				FixedIn:     packages,
			}
			vulnerabilities = append(vulnerabilities, vuln)
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

func toPackages(criteria criteria) []*database.Package {
	// There are duplicates in Red Hat .xml files.
	// This map is for deduplication.
	packagesParameters := make(map[string]*database.Package)

	possibilities := getPossibilities(criteria)
	for _, criterions := range possibilities {
		var (
			pkg       database.Package
			osVersion int
			err       error
		)

		// Attempt to parse package data from trees of criterions.
		for _, c := range criterions {
			if strings.Contains(c.Comment, " is installed") {
				const prefixLen = len("Red Hat Enterprise Linux ")
				osVersion, err = strconv.Atoi(strings.TrimSpace(c.Comment[prefixLen : prefixLen+strings.Index(c.Comment[prefixLen:], " ")]))
				if err != nil {
					log.Warningf("could not parse Red Hat release version from: '%s'.", c.Comment)
				}
			} else if strings.Contains(c.Comment, " is earlier than ") {
				const prefixLen = len(" is earlier than ")
				pkg.Name = strings.TrimSpace(c.Comment[:strings.Index(c.Comment, " is earlier than ")])
				pkg.Version, err = types.NewVersion(c.Comment[strings.Index(c.Comment, " is earlier than ")+prefixLen:])
				if err != nil {
					log.Warningf("could not parse package version '%s': %s. skipping", c.Comment[strings.Index(c.Comment, " is earlier than ")+prefixLen:], err.Error())
				}
			}
		}

		if osVersion > firstConsideredRHEL {
			pkg.OS = "centos" + ":" + strconv.Itoa(osVersion)
		} else {
			continue
		}

		if pkg.OS != "" && pkg.Name != "" && pkg.Version.String() != "" {
			packagesParameters[pkg.Key()] = &pkg
		} else {
			log.Warningf("could not determine a valid package from criterions: %v", criterions)
		}
	}

	// Convert the map to slice.
	var packagesParametersArray []*database.Package
	for _, p := range packagesParameters {
		packagesParametersArray = append(packagesParametersArray, p)
	}

	return packagesParametersArray
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
		if reference.Source == "RHSA" {
			link = reference.URI
			break
		}
	}

	return
}

func priority(def definition) types.Priority {
	// Parse the priority.
	priority := strings.TrimSpace(def.Title[strings.LastIndex(def.Title, "(")+1 : len(def.Title)-1])

	// Normalize the priority.
	switch priority {
	case "Low":
		return types.Low
	case "Moderate":
		return types.Medium
	case "Important":
		return types.High
	case "Critical":
		return types.Critical
	default:
		log.Warning("could not determine vulnerability priority from: %s.", priority)
		return types.Unknown
	}
}
