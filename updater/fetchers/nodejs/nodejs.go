// Copyright 2016 clair authors
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

package nodejs

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/updater"
	cerrors "github.com/coreos/clair/utils/errors"
	"github.com/coreos/clair/utils/types"
	"github.com/coreos/pkg/capnslog"
)

const (
	url                  = "https://api.nodesecurity.io/advisories"
	cveURLPrefix         = "http://cve.mitre.org/cgi-bin/cvename.cgi?name="
	updaterFlag          = "nodejsUpdater"
	defaultNodejsVersion = "all"
	//FIXME: Add a suffix when an advisory is fixed `after` a certain version.
	defaultVersionSuffix = "-1"
)

var log = capnslog.NewPackageLogger("github.com/coreos/clair", "updater/fetchers/nodejs")

type nodejsAdvisory struct {
	ID              int      `json:"id"`
	UpdatedAt       string   `json:"updated_at"`
	ModuleName      string   `json:"module_name"`
	CVES            []string `json:"cves"`
	PatchedVersions string   `json:"patched_versions"`
	Overview        string   `json:"overview"`
	CvssScore       float32  `json:"cvss_score"`
}

type nodejsAdvisories struct {
	Total   int              `json:"total"`
	Count   int              `json:"count"`
	Offset  int              `json:"offset"`
	Results []nodejsAdvisory `json:"results"`
}

// NodejsFetcher implements updater.Fetcher for the Node Security Project
// (https://nodesecurity.io).
type NodejsFetcher struct{}

func init() {
	updater.RegisterFetcher("nodejs", &NodejsFetcher{})
}

// FetchUpdate fetches vulnerability updates from the Node Security Project.
func (fetcher *NodejsFetcher) FetchUpdate(datastore database.Datastore) (resp updater.FetcherResponse, err error) {
	log.Info("fetching Nodejs vulnerabilities")

	// Download JSON.
	r, err := http.Get(url)
	if err != nil {
		log.Errorf("could not download Nodejs's update: %s", err)
		return resp, cerrors.ErrCouldNotDownload
	}
	defer r.Body.Close()

	// Get the latest date of the latest update's JSON data
	latestUpdate, err := datastore.GetKeyValue(updaterFlag)
	if err != nil {
		return resp, err
	}

	// Unmarshal JSON.
	var advisories nodejsAdvisories
	if err = json.NewDecoder(r.Body).Decode(&advisories); err != nil {
		log.Errorf("could not unmarshal Nodejs's JSON: %s", err)
		return resp, cerrors.ErrCouldNotParse
	}

	resp.Vulnerabilities, resp.FlagValue = parseNodejsAdvisories(advisories.Results, latestUpdate)
	resp.FlagName = updaterFlag

	return resp, nil
}

func parseNodejsAdvisories(advisories []nodejsAdvisory, latestUpdate string) (vulnerabilities []database.Vulnerability, newUpdated string) {
	mvulnerabilities := make(map[string]*database.Vulnerability)

	for _, advisory := range advisories {
		if latestUpdate >= advisory.UpdatedAt {
			break
		}
		if advisory.UpdatedAt > newUpdated {
			newUpdated = advisory.UpdatedAt
		}
		for _, vulnName := range advisory.CVES {
			// Get or create the vulnerability.
			vulnerability, vulnerabilityAlreadyExists := mvulnerabilities[vulnName]
			if !vulnerabilityAlreadyExists {
				vulnerability = &database.Vulnerability{
					Name:        vulnName,
					Link:        cveURLPrefix + strings.TrimLeft(vulnName, "CVE-"),
					Severity:    types.Unknown,
					Description: advisory.Overview,
				}
			}

			// Set the priority of the vulnerability.
			// A vulnerability has one urgency per advisory it affects.
			// The highest urgency should be the one set.
			if urgency := types.ScoreToPriority(advisory.CvssScore); urgency.Compare(vulnerability.Severity) > 0 {
				vulnerability.Severity = urgency
			}

			// Create and add the feature version.
			pkg := database.FeatureVersion{
				Feature: database.Feature{
					Name: advisory.ModuleName,
					Namespace: database.Namespace{
						Name: "nodejs:" + defaultNodejsVersion,
					},
				},
			}
			if version, err := getAdvisoryVersion(advisory.PatchedVersions); err == nil {
				pkg.Version = version
			}
			vulnerability.FixedIn = append(vulnerability.FixedIn, pkg)

			// Store the vulnerability.
			mvulnerabilities[vulnName] = vulnerability
		}
	}

	// Convert the vulnerabilities map to a slice
	for _, v := range mvulnerabilities {
		vulnerabilities = append(vulnerabilities, *v)
	}

	return
}

// getAdvisoryVersion parses a string containing one or multiple version ranges
// and returns upper-bound. By nature, this simplification may lead to false-positives
func getAdvisoryVersion(fullVersion string) (types.Version, error) {
	fixedVersion := types.MinVersion

	for _, version := range strings.Split(fullVersion, "||") {
		ovs := getOperVersions(version)
		for _, ov := range ovs {
			if ov.Oper == ">" {
				if curVersion, err := types.NewVersion(ov.Version + defaultVersionSuffix); err != nil {
					log.Warningf("could not parse package version '%s': %s. skipping", curVersion, err.Error())
				} else if curVersion.Compare(fixedVersion) > 0 {
					fixedVersion = curVersion
				}
			} else if ov.Oper == ">=" {
				if curVersion, err := types.NewVersion(ov.Version); err != nil {
					log.Warningf("could not parse package version '%s': %s. skipping", curVersion, err.Error())
				} else if curVersion.Compare(fixedVersion) > 0 {
					fixedVersion = curVersion
				}
			}
		}
	}
	if fixedVersion != types.MinVersion {
		return fixedVersion, nil
	}
	return types.MaxVersion, cerrors.ErrNotFound
}

// Clean deletes any allocated resources.
func (fetcher *NodejsFetcher) Clean() {}
