// Copyright 2019 clair authors
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

// Package nodejs implements a vulnerability source updater using the NodeJS
// Security Working Group vulnerabilities database.
package npm

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"path"
	"strconv"

	log "github.com/sirupsen/logrus"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/ext/versionfmt"
	"github.com/coreos/clair/ext/versionfmt/semver"
	"github.com/coreos/clair/ext/vulnsrc"
	"github.com/coreos/clair/pkg/gitutil"
)

const (
	nodejsSecurityWGRepoUrl = "https://github.com/nodejs/security-wg.git"
	updaterFlag             = "nodejs-securityWGVulnerabilityUpdater"
)

var ns database.Namespace

type npmSecurityAdvisory struct {
	ID                 int      `json:"id"`
	CVEs               []string `json:"cves"`
	ModuleName         string   `json:"module_name"`
	Overview           string   `json:"overview"`
	CVSSScore          float64  `json:"cvss_score"`
	VulnerableVersions string   `json:"vulnerable_versions"`
	PatchedVersions    string   `json:"patched_versions"`
}

func parseNpmVulns(repositoryPath string) ([]database.VulnerabilityWithAffected, error) {
	files, err := ioutil.ReadDir(path.Join(repositoryPath, "vuln", "npm"))
	var vulns []database.VulnerabilityWithAffected
	if err != nil {
		return vulns, err
	}

	for _, file := range files {
		if file.IsDir() {
			continue
		}

		fileName := path.Join(repositoryPath, "vuln", "npm", file.Name())
		vulnsInFile, err := parseNpmVuln(fileName)
		if err != nil {
			log.WithField("package", "NodeJS").WithField("fileName", fileName).WithError(err).Error("failed to parse vulnerability file")
			continue
		}

		vulns = append(vulns, vulnsInFile...)
	}

	return vulns, nil
}

func parseNpmVuln(filePath string) (vulns []database.VulnerabilityWithAffected, err error) {
	var data []byte
	data, err = ioutil.ReadFile(filePath)
	if err != nil {
		return
	}

	securityAdvisory := npmSecurityAdvisory{}
	if err = json.Unmarshal(data, &securityAdvisory); err != nil {
		return
	}

	if err = validSecurityAdvisory(securityAdvisory); err != nil {
		return
	}

	var ids []string
	// use CVE IDs if they exist
	if len(securityAdvisory.CVEs) > 0 {
		ids = securityAdvisory.CVEs
	} else {
		ids = []string{"NSWG-ECO-" + strconv.Itoa(securityAdvisory.ID)}
	}

	for _, id := range ids {
		vuln := database.VulnerabilityWithAffected{
			Vulnerability: database.Vulnerability{
				Name:        id,
				Namespace:   ns,
				Description: securityAdvisory.Overview,
				Link:        "https://github.com/nodejs/security-wg/blob/master/vuln/npm/" + strconv.Itoa(securityAdvisory.ID) + ".json",
				Severity:    cvssToPriority(securityAdvisory.CVSSScore),
			},
			Affected: []database.AffectedFeature{
				{
					FeatureType:     database.SourcePackage,
					FeatureName:     securityAdvisory.ModuleName,
					AffectedVersion: securityAdvisory.VulnerableVersions,
					Namespace:       ns,
				},
			},
		}

		if securityAdvisory.PatchedVersions != "" {
			vuln.Affected[0].FixedInVersion = securityAdvisory.PatchedVersions
		} else {
			vuln.Affected[0].FixedInVersion = versionfmt.MaxVersion
		}
		vulns = append(vulns, vuln)
	}

	return
}

func validSecurityAdvisory(advisory npmSecurityAdvisory) error {
	if advisory.ID == 0 {
		return errors.New("advisory ID not set")
	}
	if advisory.ModuleName == "" {
		return errors.New("module_name not set")
	}

	return nil
}

func cvssToPriority(cvssScore float64) database.Severity {
	switch {
	case cvssScore >= 9.0:
		return database.CriticalSeverity
	case cvssScore >= 7.0:
		return database.HighSeverity
	case cvssScore >= 4.0:
		return database.MediumSeverity
	case cvssScore >= 0.1:
		return database.LowSeverity
	}
	return database.UnknownSeverity
}

type updater struct {
	repositoryLocalPath string
}

func (u *updater) Update(db database.Datastore) (resp vulnsrc.UpdateResponse, err error) {
	log.WithField("package", "NodeJS").Info("start fetching vulnerabilities")
	// Pull the master branch.
	var (
		commit         string
		existingCommit string
		foundCommit    bool
	)

	if u.repositoryLocalPath, commit, err = gitutil.CloneOrPull(nodejsSecurityWGRepoUrl, u.repositoryLocalPath, updaterFlag); err != nil {
		log.WithField("package", "NodeJS").WithError(err).Error("failed to fetch vulnerabilities")
		return
	}

	// Set the updaterFlag to equal the commit processed.
	resp.FlagName = updaterFlag
	resp.FlagValue = commit
	if existingCommit, foundCommit, err = database.FindKeyValueAndRollback(db, updaterFlag); err != nil {
		return
	}

	// Short-circuit if there have been no updates.
	if foundCommit && commit == existingCommit {
		log.WithField("package", "NodeJS").Debug("no update, skip")
		return
	}

	if resp.Vulnerabilities, err = parseNpmVulns(u.repositoryLocalPath); err != nil {
		return
	}

	return
}

func (u *updater) Clean() {
	if u.repositoryLocalPath != "" {
		os.RemoveAll(u.repositoryLocalPath)
	}
}

func init() {
	ns = *database.NewNamespace("npm", semver.ParserName)
	vulnsrc.RegisterUpdater("npm", &updater{})
}
