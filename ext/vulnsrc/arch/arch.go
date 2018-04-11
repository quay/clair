// Copyright 2017-2018 clair authors
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

// Package arch implements a vulnerability source updater using the
// Arch Linux Security Tracker.
package arch

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/ext/versionfmt/rpm"
	"github.com/coreos/clair/ext/vulnsrc"
	"github.com/coreos/clair/pkg/commonerr"
)

const (
	url          = "https://security.archlinux.org/all.json"
	cveURLPrefix = "https://security.archlinux.org"
	updaterFlag  = "archUpdater"
)

type jsonData []jsonVuln

type jsonVuln struct {
	Name       string   `json:"name"`
	Packages   []string `json:"packages"`
	Status     string   `json:"status"`
	Severity   string   `json:"severity"`
	Type       string   `json:"type"`
	Affected   string   `json:"affected"`
	Fixed      string   `json:"fixed"`
	Ticket     string   `json:"ticket"`
	Issues     []string `json:"issues"`
	Advisories []string `json:"advisories"`
}

type updater struct{}

func init() {
	vulnsrc.RegisterUpdater("arch", &updater{})
}

func (u *updater) Update(datastore database.Datastore) (resp vulnsrc.UpdateResponse, err error) {
	log.WithField("package", "Arch Linux").Info("Start fetching vulnerabilities")

	tx, err := datastore.Begin()
	if err != nil {
		return resp, err
	}

	// Get the SHA-1 of the latest update's JSON data
	latestHash, ok, err := tx.FindKeyValue(updaterFlag)
	if err != nil {
		return resp, err
	}

	// NOTE(sida): The transaction won't mutate the database and I want the
	// transaction to be short.
	if err := tx.Rollback(); err != nil {
		return resp, err
	}

	if !ok {
		latestHash = ""
	}

	// Download JSON.
	r, err := http.Get(url)
	if err != nil {
		log.WithError(err).Error("could not download Arch Linux update")
		return resp, commonerr.ErrCouldNotDownload
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
		log.WithError(err).Error("could not unmarshal Arch Linux JSON")
		return resp, commonerr.ErrCouldNotParse
	}

	// Calculate the hash and skip updating if the hash has been seen before.
	hash = hex.EncodeToString(jsonSHA.Sum(nil))
	if latestKnownHash == hash {
		log.WithField("package", "Arch Linux").Debug("no update")
		return resp, nil
	}

	// Extract vulnerability data from Arch Linux JSON schema.
	resp.Vulnerabilities = parseArchLinuxJSON(&data)

	return resp, nil
}

func parseArchLinuxJSON(data *jsonData) (vulnerabilities []database.VulnerabilityWithAffected) {
	mvulnerabilities := make(map[string]*database.VulnerabilityWithAffected)

	for _, vulnNode := range *data {
		for _, vulnName := range vulnNode.Issues {
			// Get or create the vulnerability.
			vulnerability, vulnerabilityAlreadyExists := mvulnerabilities[vulnName]
			if !vulnerabilityAlreadyExists {
				vulnerability = &database.VulnerabilityWithAffected{
					Vulnerability: database.Vulnerability{
						Name:        vulnName,
						Link:        strings.Join([]string{cveURLPrefix, "/", vulnName}, ""),
						Severity:    database.UnknownSeverity,
						Description: vulnNode.Type,
					},
				}
			}

			vulnerability.Severity = severity(vulnNode.Severity)

			for _, pkgName := range vulnNode.Packages {
				// Create and add the feature version.
				pkg := database.AffectedFeature{
					FeatureName:     pkgName,
					AffectedVersion: vulnNode.Affected,
					FixedInVersion:  vulnNode.Fixed,
					Namespace: database.Namespace{
						Name:          "arch",
						VersionFormat: rpm.ParserName,
					},
				}
				vulnerability.Affected = append(vulnerability.Affected, pkg)
			}

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

func severity(severity string) database.Severity {
	switch severity {
	case "Low":
		return database.LowSeverity
	case "Medium":
		return database.MediumSeverity
	case "High":
		return database.HighSeverity
	case "Critical":
		return database.CriticalSeverity
	default:
		log.Warning("could not determine vulnerability severity from: %s.", severity)
		return database.UnknownSeverity
	}
}
