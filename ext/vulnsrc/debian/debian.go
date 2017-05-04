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

// Package debian implements a vulnerability source updater using the Debian
// Security Tracker.
package debian

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/ext/versionfmt"
	"github.com/coreos/clair/ext/versionfmt/dpkg"
	"github.com/coreos/clair/ext/vulnsrc"
	"github.com/coreos/clair/pkg/commonerr"
)

const (
	url          = "https://security-tracker.debian.org/tracker/data/json"
	cveURLPrefix = "https://security-tracker.debian.org/tracker"
	updaterFlag  = "debianUpdater"
)

type jsonData map[string]map[string]jsonVuln

type jsonVuln struct {
	Description string             `json:"description"`
	Releases    map[string]jsonRel `json:"releases"`
}

type jsonRel struct {
	FixedVersion string `json:"fixed_version"`
	Status       string `json:"status"`
	Urgency      string `json:"urgency"`
}

type updater struct{}

func init() {
	vulnsrc.RegisterUpdater("debian", &updater{})
}

func (u *updater) Update(datastore database.Datastore) (resp vulnsrc.UpdateResponse, err error) {
	log.WithField("package", "Debian").Info("Start fetching vulnerabilities")

	// Download JSON.
	r, err := http.Get(url)
	if err != nil {
		log.WithError(err).Error("could not download Debian's update")
		return resp, commonerr.ErrCouldNotDownload
	}

	// Get the SHA-1 of the latest update's JSON data
	latestHash, err := datastore.GetKeyValue(updaterFlag)
	if err != nil {
		return resp, err
	}

	// Parse the JSON.
	resp, err = buildResponse(r.Body, latestHash)
	if err != nil {
		return resp, err
	}

	return resp, nil
}

func (u *updater) Clean() {}

func buildResponse(jsonReader io.Reader, latestKnownHash string) (resp vulnsrc.UpdateResponse, err error) {
	hash := latestKnownHash

	// Defer the addition of flag information to the response.
	defer func() {
		if err == nil {
			resp.FlagName = updaterFlag
			resp.FlagValue = hash
		}
	}()

	// Create a TeeReader so that we can unmarshal into JSON and write to a SHA-1
	// digest at the same time.
	jsonSHA := sha1.New()
	teedJSONReader := io.TeeReader(jsonReader, jsonSHA)

	// Unmarshal JSON.
	var data jsonData
	err = json.NewDecoder(teedJSONReader).Decode(&data)
	if err != nil {
		log.WithError(err).Error("could not unmarshal Debian's JSON")
		return resp, commonerr.ErrCouldNotParse
	}

	// Calculate the hash and skip updating if the hash has been seen before.
	hash = hex.EncodeToString(jsonSHA.Sum(nil))
	if latestKnownHash == hash {
		log.WithField("package", "Debian").Debug("no update")
		return resp, nil
	}

	// Extract vulnerability data from Debian's JSON schema.
	var unknownReleases map[string]struct{}
	resp.Vulnerabilities, unknownReleases = parseDebianJSON(&data)

	// Log unknown releases
	for k := range unknownReleases {
		note := fmt.Sprintf("Debian %s is not mapped to any version number (eg. Jessie->8). Please update me.", k)
		resp.Notes = append(resp.Notes, note)
		log.Warning(note)
	}

	return resp, nil
}

func parseDebianJSON(data *jsonData) (vulnerabilities []database.Vulnerability, unknownReleases map[string]struct{}) {
	mvulnerabilities := make(map[string]*database.Vulnerability)
	unknownReleases = make(map[string]struct{})

	for pkgName, pkgNode := range *data {
		for vulnName, vulnNode := range pkgNode {
			for releaseName, releaseNode := range vulnNode.Releases {
				// Attempt to detect the release number.
				if _, isReleaseKnown := database.DebianReleasesMapping[releaseName]; !isReleaseKnown {
					unknownReleases[releaseName] = struct{}{}
					continue
				}

				// Skip if the status is not determined or the vulnerability is a temporary one.
				if !strings.HasPrefix(vulnName, "CVE-") || releaseNode.Status == "undetermined" {
					continue
				}

				// Get or create the vulnerability.
				vulnerability, vulnerabilityAlreadyExists := mvulnerabilities[vulnName]
				if !vulnerabilityAlreadyExists {
					vulnerability = &database.Vulnerability{
						Name:        vulnName,
						Link:        strings.Join([]string{cveURLPrefix, "/", vulnName}, ""),
						Severity:    database.UnknownSeverity,
						Description: vulnNode.Description,
					}
				}

				// Set the priority of the vulnerability.
				// In the JSON, a vulnerability has one urgency per package it affects.
				severity := SeverityFromUrgency(releaseNode.Urgency)
				if severity.Compare(vulnerability.Severity) > 0 {
					// The highest urgency should be the one set.
					vulnerability.Severity = severity
				}

				// Determine the version of the package the vulnerability affects.
				var version string
				var err error
				if releaseNode.FixedVersion == "0" {
					// This means that the package is not affected by this vulnerability.
					version = versionfmt.MinVersion
				} else if releaseNode.Status == "open" {
					// Open means that the package is currently vulnerable in the latest
					// version of this Debian release.
					version = versionfmt.MaxVersion
				} else if releaseNode.Status == "resolved" {
					// Resolved means that the vulnerability has been fixed in
					// "fixed_version" (if affected).
					err = versionfmt.Valid(dpkg.ParserName, releaseNode.FixedVersion)
					if err != nil {
						log.WithError(err).WithField("version", version).Warning("could not parse package version. skipping")
						continue
					}
					version = releaseNode.FixedVersion
				}

				// Create and add the feature version.
				pkg := database.FeatureVersion{
					Feature: database.Feature{
						Name: pkgName,
						Namespace: database.Namespace{
							Name:          "debian:" + database.DebianReleasesMapping[releaseName],
							VersionFormat: dpkg.ParserName,
						},
					},
					Version: version,
				}
				vulnerability.FixedIn = append(vulnerability.FixedIn, pkg)

				// Store the vulnerability.
				mvulnerabilities[vulnName] = vulnerability
			}
		}
	}

	// Convert the vulnerabilities map to a slice
	for _, v := range mvulnerabilities {
		vulnerabilities = append(vulnerabilities, *v)
	}

	return
}

// SeverityFromUrgency converts the urgency scale used by the Debian Security
// Bug Tracker into a database.Severity.
func SeverityFromUrgency(urgency string) database.Severity {
	switch urgency {
	case "not yet assigned":
		return database.UnknownSeverity

	case "end-of-life":
		fallthrough
	case "unimportant":
		return database.NegligibleSeverity

	case "low":
		fallthrough
	case "low*":
		fallthrough
	case "low**":
		return database.LowSeverity

	case "medium":
		fallthrough
	case "medium*":
		fallthrough
	case "medium**":
		return database.MediumSeverity

	case "high":
		fallthrough
	case "high*":
		fallthrough
	case "high**":
		return database.HighSeverity

	default:
		log.WithField("urgency", urgency).Warning("could not determine vulnerability severity from urgency")
		return database.UnknownSeverity
	}
}
