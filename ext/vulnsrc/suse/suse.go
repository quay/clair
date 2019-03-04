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

// Package suse implements a vulnerability source updater using the
// SUSE Linux and openSUSE OVAL Database.
package suse

import (
	"bufio"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/ext/versionfmt"
	"github.com/coreos/clair/ext/versionfmt/rpm"
	"github.com/coreos/clair/ext/vulnsrc"
	"github.com/coreos/clair/pkg/commonerr"
)

const (
	ovalURI = "http://ftp.suse.com/pub/projects/security/oval/"

	// "Thu, 30 Nov 2017 03:07:57 GMT
	timeFormatLastModified = "Mon, 2 Jan 2006 15:04:05 MST"

	// timestamp format 2017-10-23T04:07:14
	timeFormatOVAL = "2006-1-2T15:04:05"
)

var (
	ignoredCriterions                  []string
	suseOpenSUSEInstalledCommentRegexp = regexp.MustCompile(`(SUSE Linux Enterprise |openSUSE ).*is installed`)
	suseInstalledCommentRegexp         = regexp.MustCompile(`SUSE Linux Enterprise[A-Za-z\s]*? (\d+)[\w\s]*?(SP(\d+))? is installed`)
)

type oval struct {
	Timestamp   string       `xml:"generator>timestamp"`
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

type flavor int

const (
	SUSE flavor = iota
	OpenSUSE
)

type updater struct {
	Name          string
	NamespaceName string
	FilePrefix    string
	UpdaterFlag   string
	FileRegexp    *regexp.Regexp
}

func newUpdater(f flavor) updater {
	var up updater

	switch f {
	case SUSE:
		up.Name = "SUSE Linux"
		up.NamespaceName = "sles"
		up.FilePrefix = "suse.linux.enterprise."
		up.UpdaterFlag = "SUSEUpdater"
		up.FileRegexp = regexp.MustCompile(`suse.linux.enterprise.(\d+).xml`)
	case OpenSUSE:
		up.Name = "openSUSE"
		up.NamespaceName = "opensuse"
		up.FilePrefix = "opensuse.leap."
		up.UpdaterFlag = "openSUSEUpdater"
		up.FileRegexp = regexp.MustCompile(`opensuse.leap.(\d+\.*\d*).xml`)
	default:
		panic("tried to create an updater for an unrecognized flavor of openSUSE/SUSE")
	}

	return up
}

func init() {
	suseUpdater := newUpdater(SUSE)
	openSUSEUpdater := newUpdater(OpenSUSE)
	vulnsrc.RegisterUpdater("suse", &suseUpdater)
	vulnsrc.RegisterUpdater("opensuse", &openSUSEUpdater)
}

func (u *updater) Update(datastore database.Datastore) (resp vulnsrc.UpdateResponse, err error) {
	log.WithField("package", u.Name).Info("Start fetching vulnerabilities")

	// openSUSE and SUSE have one single xml file for all the products, there are no incremental
	// xml files. We store into the database the value of the generation timestamp
	// of the latest file we parsed.
	flagValue, ok, err := database.FindKeyValueAndRollback(datastore, u.UpdaterFlag)
	if err != nil {
		return resp, err
	}
	log.WithField("flagvalue", flagValue).Debug("Generation timestamp of latest parsed file")

	if !ok {
		flagValue = "0"
	}

	// this contains the modification time of the most recent
	// file expressed as unix time (int64)
	latestOval, err := strconv.ParseInt(flagValue, 10, 64)
	if err != nil {
		// something went wrong, force parsing of all files
		latestOval = 0
	}

	// Fetch the update list.
	r, err := http.Get(ovalURI)
	if err != nil {
		err = fmt.Errorf("Cannot download SUSE update list: %v", err)
		return resp, err
	}
	defer r.Body.Close()

	var ovalFiles []string
	var generationTimes []int64

	scanner := bufio.NewScanner(r.Body)
	for scanner.Scan() {
		line := scanner.Text()
		r := u.FileRegexp.FindStringSubmatch(line)
		if len(r) != 2 {
			continue
		}

		ovalFile := ovalURI + u.FilePrefix + r[1] + ".xml"
		log.WithFields(log.Fields{
			"ovalFile": ovalFile,
			"updater":  u.Name,
		}).Debug("file to check")

		// Do not fetch the entire file to get the value of the
		// creation time. Rely on the "latest modified time"
		// value of the file hosted on the remote server.
		timestamp, err := getLatestModifiedTime(ovalFile)
		if err != nil {
			log.WithError(err).WithField("ovalFile", ovalFile).Warning("Ignoring OVAL file")
		}

		if timestamp > latestOval {
			ovalFiles = append(ovalFiles, ovalFile)
		}
	}

	for _, oval := range ovalFiles {
		// Download the oval XML file.
		r, err := http.Get(oval)
		if err != nil {
			log.WithError(err).Error("could not download", u.Name, "update list")
			return resp, commonerr.ErrCouldNotDownload
		}
		defer r.Body.Close()

		match := u.FileRegexp.FindStringSubmatch(oval)
		if len(match) != 2 {
			log.Error("Skipping ", oval, "because it's not possible to extract osVersion")
			continue
		}
		osVersion := match[1]

		// Parse the XML.
		vs, generationTime, err := parseOval(r.Body, u.NamespaceName, osVersion)
		if err != nil {
			return resp, err
		}
		generationTimes = append(generationTimes, generationTime)

		// Collect vulnerabilities.
		resp.Vulnerabilities = append(resp.Vulnerabilities, vs...)
	}

	// Set the flag if we found anything.
	if len(generationTimes) > 0 {
		resp.FlagName = u.UpdaterFlag
		resp.FlagValue = strconv.FormatInt(latest(generationTimes), 10)
	} else {
		log.WithField("package", u.Name).Debug("no update")
	}

	return resp, nil
}

// Get the latest modification time of a remote file
// expressed as unix time
func getLatestModifiedTime(url string) (int64, error) {
	resp, err := http.Head(url)
	if err != nil {
		return 0, err
	}

	last_modified := resp.Header.Get("Last-Modified")
	if len(last_modified) == 0 {
		return 0, fmt.Errorf("last modified header missing")
	}

	timestamp, err := time.Parse(timeFormatLastModified, last_modified)
	if err != nil {
		return 0, err
	}

	return timestamp.Unix(), nil
}

func latest(values []int64) (ret int64) {
	for _, element := range values {
		if element > ret {
			ret = element
		}
	}
	return
}

func (u *updater) Clean() {}

func parseOval(ovalReader io.Reader, osFlavor, osVersion string) (vulnerabilities []database.VulnerabilityWithAffected, generationTime int64, err error) {
	// Decode the XML.
	var ov oval
	err = xml.NewDecoder(ovalReader).Decode(&ov)
	if err != nil {
		log.WithError(err).Error("could not decode XML")
		err = commonerr.ErrCouldNotParse
		return
	}

	timestamp, err := time.Parse(timeFormatOVAL, ov.Timestamp)
	if err != nil {
		return
	}
	generationTime = timestamp.Unix()

	// Iterate over the definitions and collect any vulnerabilities that affect
	// at least one package.
	for _, definition := range ov.Definitions {
		pkgs := toFeatureVersions(definition.Criteria, osFlavor, osVersion)
		if len(pkgs) > 0 {
			vulnerability := database.VulnerabilityWithAffected{
				Vulnerability: database.Vulnerability{
					Name:        name(definition),
					Link:        link(definition),
					Severity:    severity(definition),
					Description: description(definition),
				},
			}
			vulnerability.Affected = append(vulnerability.Affected, pkgs...)
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

func toFeatureVersions(criteria criteria, osFlavor, osVersion string) []database.AffectedFeature {
	// There are duplicates in SUSE .xml files.
	// This map is for deduplication.
	featureVersionParameters := make(map[string]database.AffectedFeature)

	possibilities := getPossibilities(criteria)
	for _, criterions := range possibilities {
		var featureVersion database.AffectedFeature

		// Attempt to parse package data from trees of criterions.
		for _, c := range criterions {
			if match := suseInstalledCommentRegexp.FindStringSubmatch(c.Comment); match != nil {
				if len(match) == 4 {
					osVersion = match[1]
					if match[3] != "" {
						osVersion = fmt.Sprintf("%s.%s", osVersion, match[3])
					}
				} else {
					log.WithField("comment", c.Comment).Warning("could not extract sles name and version from comment")
				}
			}

			if suseOpenSUSEInstalledCommentRegexp.FindStringSubmatch(c.Comment) == nil && strings.HasSuffix(c.Comment, " is installed") {
				name, version, err := splitPackageNameAndVersion(c.Comment[:len(c.Comment)-len(" is installed")])
				if err != nil {
					log.WithError(err).WithField("comment", c.Comment).Warning("Could not extract package name and version from comment")
				} else {
					featureVersion.FeatureName = name
					version := version
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
		}

		featureVersion.Namespace.Name = fmt.Sprintf("%s:%s", osFlavor, osVersion)
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
	return strings.TrimSpace(def.Title)
}

func link(def definition) (link string) {
	for _, reference := range def.References {
		if reference.Source == "CVE" {
			link = reference.URI
			break
		}
	}

	return
}

func severity(def definition) (severity database.Severity) {
	//TODO: handle that once openSUSE/SLE OVAL files have severity info
	return database.UnknownSeverity
}

func splitPackageNameAndVersion(fullname string) (name, version string, err error) {
	re := regexp.MustCompile(`-\d+\.`)

	matches := re.FindStringSubmatchIndex(fullname)
	if matches == nil {
		err = fmt.Errorf("Cannot extract package name and version from %s", fullname)
	} else {
		name = fullname[:matches[0]]
		version = fullname[matches[0]+1:]
	}

	return
}
