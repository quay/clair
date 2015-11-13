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
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/coreos/quay-sec/database"
	cerrors "github.com/coreos/quay-sec/utils/errors"
	"github.com/coreos/quay-sec/updater"
	"github.com/coreos/quay-sec/utils/types"
)

const (
	url               = "https://security-tracker.debian.org/tracker/data/json"
	cveURLPrefix      = "https://security-tracker.debian.org/tracker"
	debianUpdaterFlag = "debianUpdater"
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

// DebianFetcher implements updater.Fetcher for the Debian Security Tracker
// (https://security-tracker.debian.org).
type DebianFetcher struct{}

func init() {
	updater.RegisterFetcher("debian", &DebianFetcher{})
}

// FetchUpdate fetches vulnerability updates from the Debian Security Tracker.
func (fetcher *DebianFetcher) FetchUpdate() (resp updater.FetcherResponse, err error) {
	log.Info("fetching Debian vulneratibilities")

	// Download JSON.
	r, err := http.Get(url)
	if err != nil {
		log.Errorf("could not download Debian's update: %s", err)
		return resp, cerrors.ErrCouldNotDownload
	}

	// Get the SHA-1 of the latest update's JSON data
	latestHash, err := database.GetFlagValue(debianUpdaterFlag)
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

func buildResponse(jsonReader io.Reader, latestKnownHash string) (resp updater.FetcherResponse, err error) {
	hash := latestKnownHash

	// Defer the addition of flag information to the response.
	defer func() {
		if err == nil {
			resp.FlagName = debianUpdaterFlag
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
		log.Errorf("could not unmarshal Debian's JSON: %s", err)
		return resp, ErrCouldNotParse
	}

	// Calculate the hash and skip updating if the hash has been seen before.
	hash = hex.EncodeToString(jsonSHA.Sum(nil))
	if latestKnownHash == hash {
		log.Debug("no Debian update")
		return resp, nil
	}

	// Extract vulnerability data from Debian's JSON schema.
	vulnerabilities, unknownReleases := parseDebianJSON(&data)

	// Log unknown releases
	for k := range unknownReleases {
		note := fmt.Sprintf("Debian %s is not mapped to any version number (eg. Jessie->8). Please update me.", k)
		resp.Notes = append(resp.Notes, note)
		log.Warning(note)
	}

	// Convert the vulnerabilities map to a slice in the response
	for _, v := range vulnerabilities {
		resp.Vulnerabilities = append(resp.Vulnerabilities, v)
	}

	return resp, nil
}

func parseDebianJSON(data *jsonData) (vulnerabilities map[string]updater.FetcherVulnerability, unknownReleases map[string]struct{}) {
	vulnerabilities = make(map[string]updater.FetcherVulnerability)
	unknownReleases = make(map[string]struct{})

	for pkgName, pkgNode := range *data {
		for vulnName, vulnNode := range pkgNode {
			for releaseName, releaseNode := range vulnNode.Releases {
				// Attempt to detect the release number.
				if _, isReleaseKnown := database.DebianReleasesMapping[releaseName]; !isReleaseKnown {
					unknownReleases[releaseName] = struct{}{}
					continue
				}

				// Skip if the release is not affected.
				if releaseNode.FixedVersion == "0" || releaseNode.Status == "undetermined" {
					continue
				}

				// Get or create the vulnerability.
				vulnerability, vulnerabilityAlreadyExists := vulnerabilities[vulnName]
				if !vulnerabilityAlreadyExists {
					vulnerability = updater.FetcherVulnerability{
						ID:          vulnName,
						Link:        strings.Join([]string{cveURLPrefix, "/", vulnName}, ""),
						Priority:    types.Unknown,
						Description: vulnNode.Description,
					}
				}

				// Set the priority of the vulnerability.
				// In the JSON, a vulnerability has one urgency per package it affects.
				// The highest urgency should be the one set.
				urgency := urgencyToPriority(releaseNode.Urgency)
				if urgency.Compare(vulnerability.Priority) > 0 {
					vulnerability.Priority = urgency
				}

				// Determine the version of the package the vulnerability affects.
				var version types.Version
				var err error
				if releaseNode.Status == "open" {
					// Open means that the package is currently vulnerable in the latest
					// version of this Debian release.
					version = types.MaxVersion
				} else if releaseNode.Status == "resolved" {
					// Resolved means that the vulnerability has been fixed in
					// "fixed_version" (if affected).
					version, err = types.NewVersion(releaseNode.FixedVersion)
					if err != nil {
						log.Warningf("could not parse package version '%s': %s. skipping", releaseNode.FixedVersion, err.Error())
						continue
					}
				}

				// Create and add the package.
				pkg := &database.Package{
					OS:      "debian:" + database.DebianReleasesMapping[releaseName],
					Name:    pkgName,
					Version: version,
				}
				vulnerability.FixedIn = append(vulnerability.FixedIn, pkg)

				// Store the vulnerability.
				vulnerabilities[vulnName] = vulnerability
			}
		}
	}

	return
}

func urgencyToPriority(urgency string) types.Priority {
	switch urgency {
	case "not yet assigned":
		return types.Unknown

	case "end-of-life":
		fallthrough
	case "unimportant":
		return types.Negligible

	case "low":
		fallthrough
	case "low*":
		fallthrough
	case "low**":
		return types.Low

	case "medium":
		fallthrough
	case "medium*":
		fallthrough
	case "medium**":
		return types.Medium

	case "high":
		fallthrough
	case "high*":
		fallthrough
	case "high**":
		return types.High

	default:
		log.Warningf("could not determine vulnerability priority from: %s", urgency)
		return types.Unknown
	}
}
