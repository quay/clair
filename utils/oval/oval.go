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

// This package contains the OvalFetcher definition which is being used
// for fetching update information on OVAL format
// see: https://oval.mitre.org/about/faqs.html#a1
//
// Example of an oval definition
// <oval_definitions xmlns=.....>
//  <definitions>
//    <definition>
//      <metadata>
//        <title>CVE-1111-11</title>
//        <description>blablabla</description>
//        <reference source="CVE" ref_id="CVE-1111-11" ref_url="http...."/>
//        <reference source="RHSA" ref_id="RHSA-111:11" ref_url="http...."/>
//      </metadata>
//      <criteria operator="AND">
//        <criterion test_ref="123" comment="glibc is ....">
//        </criterion>
//        <criterion test_ref="456" comment=".... is signed with Red Hat....">
//        </criterion>
//      </criteria>
//    </definition>
//  </definitions>
//  <tests>
//  ...
//  </tests>
//  <objects>
//  ...
//  </objects>
//  <states>
//  ...
//  </states>
// </oval_definitions>
// see more complete examples here
// https://oval.mitre.org/language/about/definition.html
// The methods here use an interface (see below) that must be implemented for
// each Distribution in updated/fetchers/
package oval

import (
	"bufio"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/updater"
	cerrors "github.com/coreos/clair/utils/errors"
	"github.com/coreos/clair/utils/types"
	"github.com/coreos/pkg/capnslog"
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

// OvalFetcher implements updater.Fetcher.
type OvalFetcher struct {
	// OsInfo contains specifics to each Linux Distribution (see below)
	OsInfo OSInfo
}

// OSInfo interface contains specifics methods for parsing OVAL definitions
// that must be implemented by each Linux Distribution that uses OVAL
// i.e. Red Hat and SUSE
type OSInfo interface {
	// ParsePackageNameVersion should, given a comment in a criterion, return
	// the name and the version of the package.
	// For example, if the comment is
	//   glibc is earlier than 3.2
	// it should return glibc and 3.2.
	//
	// This is based on the assumption that the distributions generate the
	// comments automatically and they won't change (I know, not very
	// reliable...).
	ParsePackageNameVersion(comment string) (string, string)

	// ParseOsVersion should, given a comment in a criterion, return the
	// version of the Operating System.
	// For example, if the comment is
	//   SUSE Linux Enterpise Server 12 is installed
	// should return 12
	//
	// This is based on the assumption that the distributions generate the
	// comments automatically and they won't change it (I know, not very
	// reliable...).
	ParseOsVersion(comment string) string

	// Given a line, parse for the xml file that contains the oval definition
	// and returns the filename.
	// For example if the line contains
	//	 com.redhat.rhsa-2003.xml, this will be returned.
	//
	// This is being used in conjunction with OvalUri (see below). Oval Uri
	// contains a list of files, and you need ParseFilenameDist to get the
	// right ones.
	ParseFilenameDist(line string) string

	// OvalUri returns the url where the oval definitions are stored for given
	// distributions. See examples:
	//   https://www.redhat.com/security/data/oval/
	//   http://ftp.suse.com/pub/projects/security/oval/
	OvalURI() string

	// DistName returns the distribution name. Mostly used for debugging
	// purposes.
	DistName() string

	// IgnoredCriterions returns a list of strings that must be ignored when
	// parsing the criterions.
	// Oval parses parses all criterions by default trying to identify either
	// package name and version or distribution version.
	IgnoredCriterions() []string

	// SecToken returns a string that is compared with the value of
	// reference.source in order to know if that is a security reference for,
	// for example, using its url value.
	// Example return values: CVE, RHSA.
	SecToken() string

	// Namespace stores the namespace that will be used in clair to store the
	// vulnerabilities.
	Namespace() string
}

var (
	log = capnslog.NewPackageLogger("github.com/coreos/clair", "utils/oval")
)

// FetchUpdate gets vulnerability updates from the OVAL definitions.
func (f *OvalFetcher) FetchUpdate(datastore database.Datastore) (resp updater.FetcherResponse, err error) {
	log.Info("fetching %s vulnerabilities", f.OsInfo.DistName())

	r, err := http.Get(f.OsInfo.OvalURI())
	if err != nil {
		log.Errorf("could not download %s's update list: %s", f.OsInfo.DistName(), err)
		return resp, cerrors.ErrCouldNotDownload
	}

	var distList []string
	scanner := bufio.NewScanner(r.Body)

	for scanner.Scan() {
		line := scanner.Text()
		filename := f.OsInfo.ParseFilenameDist(line)
		if filename != "" {
			distList = append(distList, filename)
		}
	}

	for _, filename := range distList {
		r, err := http.Get(filename)
		if err != nil {
			log.Errorf("could not download %s's update file: %s", f.OsInfo.DistName(), err)
			return resp, cerrors.ErrCouldNotDownload
		}

		vs, err := f.ParseOval(r.Body)
		if err != nil {
			return resp, err
		}

		resp.Vulnerabilities = append(resp.Vulnerabilities, vs...)
	}

	// Set the flag if we found anything.
	if len(distList) > 0 {
		resp.FlagName = f.OsInfo.DistName() + "_updater"
		resp.FlagValue = distList[len(distList)-1]
	} else {
		log.Debug("no files to parse found for %s", f.OsInfo.DistName())
		log.Debug("in %s", f.OsInfo.OvalURI())
	}

	return resp, nil
}

// Clean deletes any allocated resources.
func (f *OvalFetcher) Clean() {}

// Parse criterions into an array of FeatureVersion for storing into the database
func (f *OvalFetcher) ToFeatureVersions(possibilities [][]criterion) []database.FeatureVersion {
	featureVersionParameters := make(map[string]database.FeatureVersion)

	for _, criterions := range possibilities {
		var (
			featureVersion database.FeatureVersion
			osVersion      string
		)

		for _, c := range criterions {
			if osVersion != "" && featureVersion.Feature.Name != "" &&
				featureVersion.Version.String() != "" {
				break
			}
			tmp_v := f.OsInfo.ParseOsVersion(c.Comment)
			if tmp_v != "" {
				osVersion = tmp_v
				continue
			}

			tmp_p_name, tmp_p_version := f.OsInfo.ParsePackageNameVersion(c.Comment)
			if tmp_p_version != "" && tmp_p_name != "" {
				featureVersion.Feature.Name = tmp_p_name
				featureVersion.Version, _ = types.NewVersion(tmp_p_version)
				continue
			}

			log.Warningf("could not parse criteria: '%s'.", c.Comment)
		}

		if osVersion == "" {
			log.Warning("No OS version found for criterions")
			log.Warning(criterions)
			continue
		}

		featureVersion.Feature.Namespace.Name = fmt.Sprintf("%s:%s", f.OsInfo.Namespace(), osVersion)

		if featureVersion.Feature.Name != "" && featureVersion.Version.String() != "" {
			featureVersionParameters[featureVersion.Feature.Namespace.Name+":"+featureVersion.Feature.Name] = featureVersion
		} else {
			log.Warningf("could not determine a valid package from criterions: %v", criterions)
		}
	}

	var featureVersionParametersArray []database.FeatureVersion
	for _, fv := range featureVersionParameters {
		featureVersionParametersArray = append(featureVersionParametersArray, fv)
	}

	return featureVersionParametersArray
}

// Parse an Oval file.
func (f *OvalFetcher) ParseOval(ovalReader io.Reader) (vulnerabilities []database.Vulnerability, err error) {
	var ov oval
	err = xml.NewDecoder(ovalReader).Decode(&ov)
	if err != nil {
		log.Errorf("could not decode %s's XML: %s", f.OsInfo.DistName(), err)
		return vulnerabilities, cerrors.ErrCouldNotParse
	}

	for _, definition := range ov.Definitions {
		pkgs := f.ToFeatureVersions(f.Possibilities(definition.Criteria))

		if len(pkgs) > 0 {
			vulnerability := database.Vulnerability{
				Name:        name(definition),
				Link:        link(definition, f.OsInfo.SecToken()),
				Severity:    priority(definition),
				Description: description(definition),
			}

			vulnerability.FixedIn = append(vulnerability.FixedIn, pkgs...)

			vulnerabilities = append(vulnerabilities, vulnerability)
		}
	}

	return
}

// Get the description from a definition element
func description(def definition) (desc string) {
	desc = strings.Replace(def.Description, "\n\n\n", " ", -1)
	desc = strings.Replace(desc, "\n\n", " ", -1)
	desc = strings.Replace(desc, "\n", " ", -1)

	return
}

// Get the name form a definition element
func name(def definition) string {
	title := def.Title
	index := strings.Index(title, ": ")
	if index == -1 {
		index = len(title)
	}
	return strings.TrimSpace(title[:index])
}

// Get the link from a definition element where reference.source matches the secToken
func link(def definition, secToken string) (link string) {
	for _, reference := range def.References {
		if reference.Source == secToken {
			link = reference.URI
			break
		}
	}

	return
}

// Get priority from a definition
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

// Get Criterions elements from a criteria element
func (f *OvalFetcher) Criterions(node criteria) [][]criterion {
	var criterions []criterion

	for _, c := range node.Criterions {
		ignored := false
		for _, ignoredItem := range f.OsInfo.IgnoredCriterions() {
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

// Get Possibilities from a criteria element
func (f *OvalFetcher) Possibilities(node criteria) [][]criterion {
	if len(node.Criterias) == 0 {
		return f.Criterions(node)
	}

	var possibilitiesToCompose [][][]criterion

	for _, criteria := range node.Criterias {
		possibilitiesToCompose = append(possibilitiesToCompose, f.Possibilities(*criteria))
	}

	if len(node.Criterions) > 0 {
		possibilitiesToCompose = append(possibilitiesToCompose, f.Criterions(node))
	}

	var possibilities [][]criterion

	if node.Operator == "AND" {
		possibilities = append(possibilities, possibilitiesToCompose[0]...)

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
			possibilities = append(possibilities, possibilityGroup...)
		}
	}
	return possibilities
}
