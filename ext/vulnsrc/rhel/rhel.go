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
	"compress/bzip2"
	"compress/gzip"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/quay/clair/v2/database"
	"github.com/quay/clair/v2/ext/versionfmt"
	"github.com/quay/clair/v2/ext/versionfmt/rpm"
	"github.com/quay/clair/v2/ext/vulnsrc"
	"github.com/quay/clair/v2/pkg/commonerr"
)

const (
	firstConsideredRHEL = 5
	updaterFlag         = "rhelUpdater"
	dbURL               = `https://www.redhat.com/security/data/oval/com.redhat.rhsa-RHEL%d.xml`
)

var (
	ignoredCriterions = []string{
		" is signed with Red Hat ",
		" Client is installed",
		" Workstation is installed",
		" ComputeNode is installed",
	}

	rhsaRegexp = regexp.MustCompile(`com.redhat.rhsa-(\d+).xml`)
	releases   = []int{4, 5, 6, 7, 8}
	httpClient = http.Client{
		Timeout: 5 * time.Minute,
	}
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

type updater struct{}

func init() {
	vulnsrc.RegisterUpdater("rhel", &updater{})
}

func (u *updater) Update(datastore database.Datastore) (resp vulnsrc.UpdateResponse, err error) {
	log.WithField("package", "RHEL").Info("Start fetching vulnerabilities")

	// flagValue is http.TimeFormat
	var useLastModifiedHeader bool = true
	flagValue, err := datastore.GetKeyValue(updaterFlag)
	if err != nil {
		return resp, err
	}
	// if we cannot parse the flag as a timestamp we'll fix it
	// this time around.
	_, err = time.Parse(http.TimeFormat, flagValue)
	if err != nil {
		useLastModifiedHeader = false
	}

	notModified := false
	ts := time.Now().UTC().Format(http.TimeFormat)
	for _, release := range releases {
		url := fmt.Sprintf(dbURL, release)
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return resp, fmt.Errorf("failed to create request: %v", err)
		}
		if useLastModifiedHeader {
			req.Header.Set("If-Modified-Since", flagValue)
		}

		r, err := httpClient.Do(req)
		switch {
		case err != nil:
			return resp, fmt.Errorf("failed to download %s: %v", url, err)
		case r.StatusCode == http.StatusNotModified:
			notModified = true
			log.WithField("package", "Red Hat").Infof("%s has not been modified since %v. no update necessary", url, flagValue)
			continue
		case r.StatusCode != http.StatusOK:
			log.WithField("package", "Red Hat").Debugf("%s request failed with %s", url, r.Status)
			continue
		}

		var reader io.Reader
		switch r.Header.Get("Content-Type") {
		case "application/gzip":
			reader, _ = gzip.NewReader(r.Body)
		case "application/x-bzip2":
			reader = bzip2.NewReader(r.Body)
		default:
			reader = r.Body
		}

		// Parse the XML.
		vs, err := parseRHSA(reader)
		if err != nil {
			return resp, err
		}

		// Collect vulnerabilities.
		for _, v := range vs {
			resp.Vulnerabilities = append(resp.Vulnerabilities, v)
		}
	}

	if notModified || len(resp.Vulnerabilities) != 0 {
		resp.FlagName = updaterFlag
		resp.FlagValue = ts
	}
	return resp, nil
}

func (u *updater) Clean() {}

func parseRHSA(ovalReader io.Reader) (vulnerabilities []database.Vulnerability, err error) {
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
		pkgs := toFeatureVersions(definition.Criteria)
		if len(pkgs) > 0 {
			vulnerability := database.Vulnerability{
				Name:        name(definition),
				Link:        link(definition),
				Severity:    severity(definition),
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
	// There are duplicates in Red Hat .xml files.
	// This map is for deduplication.
	featureVersionParameters := make(map[string]database.FeatureVersion)

	possibilities := getPossibilities(criteria)
	for _, criterions := range possibilities {
		var (
			featureVersion database.FeatureVersion
			osVersion      int
			err            error
		)

		const (
			rhelPrefix = "Red Hat Enterprise Linux "
		)

		// Attempt to parse package data from trees of criterions.
		for _, c := range criterions {
			if strings.Contains(c.Comment, " is installed") && strings.HasPrefix(c.Comment, rhelPrefix) {
				const prefixLen = len(rhelPrefix)
				osVersion, err = strconv.Atoi(strings.TrimSpace(c.Comment[prefixLen : prefixLen+strings.Index(c.Comment[prefixLen:], " ")]))
				if err != nil {
					log.WithField("criterion comment", c.Comment).Warning("could not parse Red Hat release version from criterion comment")
				}
			} else if strings.Contains(c.Comment, " is earlier than ") {
				const prefixLen = len(" is earlier than ")
				featureVersion.Feature.Name = strings.TrimSpace(c.Comment[:strings.Index(c.Comment, " is earlier than ")])
				version := c.Comment[strings.Index(c.Comment, " is earlier than ")+prefixLen:]
				err := versionfmt.Valid(rpm.ParserName, version)
				if err != nil {
					log.WithError(err).WithField("version", version).Warning("could not parse package version. skipping")
				} else {
					featureVersion.Version = version
					featureVersion.Feature.Namespace.VersionFormat = rpm.ParserName
				}
			}
		}

		if osVersion >= firstConsideredRHEL {
			// TODO(vbatts) this is where features need multiple labels ('centos' and 'rhel')
			featureVersion.Feature.Namespace.Name = "centos" + ":" + strconv.Itoa(osVersion)
		} else {
			continue
		}

		if featureVersion.Feature.Namespace.Name != "" && featureVersion.Feature.Name != "" && featureVersion.Version != "" {
			featureVersionParameters[featureVersion.Feature.Namespace.Name+":"+featureVersion.Feature.Name] = featureVersion
		} else {
			log.WithField("criterions", fmt.Sprintf("%v", criterions)).Warning("could not determine a valid package from criterions")
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
		if reference.Source == "RHSA" {
			link = reference.URI
			break
		}
	}

	return
}

func severity(def definition) database.Severity {
	switch strings.TrimSpace(def.Title[strings.LastIndex(def.Title, "(")+1 : len(def.Title)-1]) {
	case "None":
		return database.NegligibleSeverity
	case "Low":
		return database.LowSeverity
	case "Moderate":
		return database.MediumSeverity
	case "Important":
		return database.HighSeverity
	case "Critical":
		return database.CriticalSeverity
	default:
		log.Debugf("could not determine vulnerability severity from: %s.", def.Title)
		return database.UnknownSeverity
	}
}
