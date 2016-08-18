// Copyright 2015 clair authors
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

package oracle

import (
	"bufio"
	"encoding/xml"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/updater"
	cerrors "github.com/coreos/clair/utils/errors"
	"github.com/coreos/clair/utils/types"
	"github.com/coreos/pkg/capnslog"
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

	log = capnslog.NewPackageLogger("github.com/coreos/clair", "updater/fetchers/oracle")
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

// OracleFetcher implements updater.Fetcher and gets vulnerability updates from
// the Oracle Linux OVAL definitions.
type OracleFetcher struct{}

func init() {
	updater.RegisterFetcher("Oracle", &OracleFetcher{})
}

// FetchUpdate gets vulnerability updates from the Oracle Linux OVAL definitions.
func (f *OracleFetcher) FetchUpdate(datastore database.Datastore) (resp updater.FetcherResponse, err error) {
	log.Info("fetching Oracle Linux vulnerabilities")

	// Get the first ELSA we have to manage.
	flagValue, err := datastore.GetKeyValue(updaterFlag)
	if err != nil {
		return resp, err
	}

	firstELSA, err := strconv.Atoi(flagValue)
	if firstELSA == 0 || err != nil {
		firstELSA = firstOracle5ELSA
	}


	// Fetch the update list.
	r, err := http.Get(ovalURI)
	if err != nil {
		log.Errorf("could not download Oracle's update list: %s", err)
		return resp, cerrors.ErrCouldNotDownload
	}

	// Get the list of ELSAs that we have to process.
	var elsaList []int
	scanner := bufio.NewScanner(r.Body)
	for scanner.Scan() {
		line := scanner.Text()
		r := elsaRegexp.FindStringSubmatch(line)
		if len(r) == 2 {
			elsaNo, _ := strconv.Atoi(r[1])
			if elsaNo > firstELSA {
				elsaList = append(elsaList, elsaNo)
			}
		}
	}

	for _, elsa := range elsaList {
		// Download the ELSA's XML file.
		r, err := http.Get(ovalURI + elsaFilePrefix + strconv.Itoa(elsa) + ".xml")
		if err != nil {
			log.Errorf("could not download Oracle's update file: %s", err)
			return resp, cerrors.ErrCouldNotDownload
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
		resp.FlagValue = strconv.Itoa(elsaList[len(elsaList)-1])
	} else {
		log.Debug("no Oracle Linux update.")
	}

	return resp, nil
}

func parseELSA(ovalReader io.Reader) (vulnerabilities []database.Vulnerability, err error) {
	// Decode the XML.
	var ov oval
	err = xml.NewDecoder(ovalReader).Decode(&ov)
	if err != nil {
		log.Errorf("could not decode Oracle's XML: %s", err)
		err = cerrors.ErrCouldNotParse
		return
	}

	// Iterate over the definitions and collect any vulnerabilities that affect
	// at least one package.
	for _, definition := range ov.Definitions {
		pkgs := toFeatureVersions(definition.Criteria)
		if len(pkgs) > 0 {
			vulnerability := database.Vulnerability{
				Name:        name(definition),
				Link:        link(definition),
				Severity:    priority(definition),
				Description: description(definition),
			}
			for _, p := range pkgs {
				vulnerability.FixedIn = append(vulnerability.FixedIn, p)
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

func toFeatureVersions(criteria criteria) []database.FeatureVersion {
	// There are duplicates in Oracle .xml files.
	// This map is for deduplication.
	featureVersionParameters := make(map[string]database.FeatureVersion)

	possibilities := getPossibilities(criteria)
	for _, criterions := range possibilities {
		var (
			featureVersion database.FeatureVersion
			osVersion      int
			err            error
		)

		// Attempt to parse package data from trees of criterions.
		for _, c := range criterions {
			if strings.Contains(c.Comment, " is installed") {
				const prefixLen = len("Oracle Linux ")
				osVersion, err = strconv.Atoi(strings.TrimSpace(c.Comment[prefixLen : prefixLen+strings.Index(c.Comment[prefixLen:], " ")]))
				if err != nil {
					log.Warningf("could not parse Oracle Linux release version from: '%s'.", c.Comment)
				}
			} else if strings.Contains(c.Comment, " is earlier than ") {
				const prefixLen = len(" is earlier than ")
				featureVersion.Feature.Name = strings.TrimSpace(c.Comment[:strings.Index(c.Comment, " is earlier than ")])
				featureVersion.Version, err = types.NewVersion(c.Comment[strings.Index(c.Comment, " is earlier than ")+prefixLen:])
				if err != nil {
					log.Warningf("could not parse package version '%s': %s. skipping", c.Comment[strings.Index(c.Comment, " is earlier than ")+prefixLen:], err.Error())
				}
			}
		}

		featureVersion.Feature.Namespace.Name = "oracle" + ":" + strconv.Itoa(osVersion)

		if featureVersion.Feature.Namespace.Name != "" && featureVersion.Feature.Name != "" && featureVersion.Version.String() != "" {
			featureVersionParameters[featureVersion.Feature.Namespace.Name+":"+featureVersion.Feature.Name] = featureVersion
		} else {
			log.Warningf("could not determine a valid package from criterions: %v", criterions)
		}
	}

	// Convert the map to slice.
	var featureVersionParametersArray []database.FeatureVersion
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

func priority(def definition) types.Priority {
	// Parse the priority.
	priority := strings.TrimSpace(def.Title[strings.LastIndex(def.Title, "(")+1 : len(def.Title)-2])

	// Normalize the priority.
	switch priority {
	case "NA":
		return types.Negligible
	case "LOW":
		return types.Low
	case "MODERATE":
		return types.Medium
	case "IMPORTANT":
		return types.High
	case "CRITICAL":
		return types.Critical
	default:
		log.Warning("could not determine vulnerability priority from: %s.", priority)
		return types.Unknown
	}
}

// Clean deletes any allocated resources.
func (f *OracleFetcher) Clean() {}
