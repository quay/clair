// Copyright 2018 clair authors
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

// Package ubuntu implements a vulnerability source updater using the
// Ubuntu CVE Tracker.
package ubuntu

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/ext/versionfmt"
	"github.com/coreos/clair/ext/versionfmt/dpkg"
	"github.com/coreos/clair/ext/vulnsrc"
	"github.com/coreos/clair/pkg/gitutil"
)

const (
	trackerURI   = "https://git.launchpad.net/ubuntu-cve-tracker"
	updaterFlag  = "ubuntuUpdater"
	cveURL       = "http://people.ubuntu.com/~ubuntu-security/cve/%s"
	affectedType = database.SourcePackage
)

var (
	ubuntuIgnoredReleases = map[string]struct{}{
		"upstream": {},
		"devel":    {},

		"dapper":   {},
		"edgy":     {},
		"feisty":   {},
		"gutsy":    {},
		"hardy":    {},
		"intrepid": {},
		"jaunty":   {},
		"karmic":   {},
		"lucid":    {},
		"maverick": {},
		"natty":    {},
		"oneiric":  {},
		"saucy":    {},

		"vivid/ubuntu-core":          {},
		"vivid/stable-phone-overlay": {},

		// Syntax error
		"Patches": {},
		// Product
		"product": {},
	}

	affectsCaptureRegexp      = regexp.MustCompile(`(?P<release>.*)_(?P<package>.*): (?P<status>[^\s]*)( \(+(?P<note>[^()]*)\)+)?`)
	affectsCaptureRegexpNames = affectsCaptureRegexp.SubexpNames()

	errUnknownRelease = errors.New("found packages with CVEs for a verison of Ubuntu that Clair doesn't know about")
)

type updater struct {
	repositoryLocalPath string
}

func init() {
	vulnsrc.RegisterUpdater("ubuntu", &updater{})
}

func (u *updater) Update(db database.Datastore) (resp vulnsrc.UpdateResponse, err error) {
	log.WithField("package", "Ubuntu").Info("Start fetching vulnerabilities")

	// Pull the master branch.
	var commit string
	u.repositoryLocalPath, commit, err = gitutil.CloneOrPull(trackerURI, u.repositoryLocalPath, updaterFlag)
	if err != nil {
		return resp, err
	}

	// Ask the database for the latest commit we successfully applied.
	dbCommit, ok, err := database.FindKeyValueAndRollback(db, updaterFlag)
	if err != nil {
		return
	}

	if !ok {
		dbCommit = ""
	}

	// Set the updaterFlag to equal the commit processed.
	resp.FlagName = updaterFlag
	resp.FlagValue = commit

	// Short-circuit if there have been no updates.
	if commit == dbCommit {
		log.WithField("package", "ubuntu").Debug("no update")
		return
	}

	// Get the list of vulnerabilities that we have to update.
	var modifiedCVE map[string]struct{}
	modifiedCVE, err = collectModifiedVulnerabilities(commit, dbCommit, u.repositoryLocalPath)
	if err != nil {
		return
	}

	// Get the list of vulnerabilities.
	resp.Vulnerabilities, resp.Notes, err = collectVulnerabilitiesAndNotes(u.repositoryLocalPath, modifiedCVE)
	if err != nil {
		return
	}

	// The only notes we take are if we encountered unknown Ubuntu release.
	// We don't want the commit to be considered as managed in that case.
	if len(resp.Notes) != 0 {
		resp.FlagValue = dbCommit
	}

	return
}

func (u *updater) Clean() {
	if u.repositoryLocalPath != "" {
		os.RemoveAll(u.repositoryLocalPath)
	}
}

func collectModifiedVulnerabilities(commit, dbCommit, repositoryLocalPath string) (map[string]struct{}, error) {
	modifiedCVE := make(map[string]struct{})
	for _, dirName := range []string{"active", "retired"} {
		if err := processDirectory(repositoryLocalPath, dirName, modifiedCVE); err != nil {
			return nil, err
		}
	}
	return modifiedCVE, nil
}

func processDirectory(repositoryLocalPath, dirName string, modifiedCVE map[string]struct{}) error {
	// Open the directory.
	d, err := os.Open(filepath.Join(repositoryLocalPath, dirName))
	if err != nil {
		log.WithError(err).Error("could not open Ubuntu vulnerabilities repository's folder")
		return vulnsrc.ErrFilesystem
	}
	defer d.Close()

	// Get the FileInfo of all the files in the directory.
	names, err := d.Readdirnames(-1)
	if err != nil {
		log.WithError(err).Error("could not read Ubuntu vulnerabilities repository's folder")
		return vulnsrc.ErrFilesystem
	}

	// Add the vulnerabilities to the list.
	for _, name := range names {
		if strings.HasPrefix(name, "CVE-") {
			modifiedCVE[dirName+"/"+name] = struct{}{}
		}
	}

	return nil
}

func collectVulnerabilitiesAndNotes(repositoryLocalPath string, modifiedCVE map[string]struct{}) ([]database.VulnerabilityWithAffected, []string, error) {
	vulns := make([]database.VulnerabilityWithAffected, 0)
	noteSet := make(map[string]struct{})

	for cvePath := range modifiedCVE {
		// Open the CVE file.
		file, err := os.Open(filepath.Join(repositoryLocalPath, cvePath))
		if err != nil {
			// This can happen when a file is modified then moved in another commit.
			continue
		}

		// Parse the vulnerability.
		v, unknownReleases, err := parseUbuntuCVE(file)
		if err != nil {
			file.Close()
			return nil, nil, err
		}

		// Add the vulnerability to the response.
		vulns = append(vulns, v)

		// Store any unknown releases as notes.
		for k := range unknownReleases {
			noteSet[errUnknownRelease.Error()+": "+k] = struct{}{}
		}

		file.Close()
	}

	// Convert the note set into a slice.
	var notes []string
	for note := range noteSet {
		notes = append(notes, note)
	}

	return vulns, notes, nil
}

func parseUbuntuCVE(fileContent io.Reader) (vulnerability database.VulnerabilityWithAffected, unknownReleases map[string]struct{}, err error) {
	unknownReleases = make(map[string]struct{})
	readingDescription := false
	scanner := bufio.NewScanner(fileContent)

	// only unique major releases will be considered. All sub releases' (e.g.
	// precise/esm) features are considered belong to major releases.
	uniqueRelease := map[string]struct{}{}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip any comments.
		if strings.HasPrefix(line, "#") {
			continue
		}

		// Parse the name.
		if strings.HasPrefix(line, "Candidate:") {
			vulnerability.Name = strings.TrimSpace(strings.TrimPrefix(line, "Candidate:"))
			vulnerability.Link = fmt.Sprintf(cveURL, vulnerability.Name)
			continue
		}

		// Parse the priority.
		if strings.HasPrefix(line, "Priority:") {
			priority := strings.TrimSpace(strings.TrimPrefix(line, "Priority:"))

			// Handle syntax error: Priority: medium (heap-protector)
			if strings.Contains(priority, " ") {
				priority = priority[:strings.Index(priority, " ")]
			}

			vulnerability.Severity = SeverityFromPriority(priority)
			continue
		}

		// Parse the description.
		if strings.HasPrefix(line, "Description:") {
			readingDescription = true
			vulnerability.Description = strings.TrimSpace(strings.TrimPrefix(line, "Description:")) // In case there is a formatting error and the description starts on the same line
			continue
		}
		if readingDescription {
			if strings.HasPrefix(line, "Ubuntu-Description:") || strings.HasPrefix(line, "Notes:") || strings.HasPrefix(line, "Bugs:") || strings.HasPrefix(line, "Priority:") || strings.HasPrefix(line, "Discovered-by:") || strings.HasPrefix(line, "Assigned-to:") {
				readingDescription = false
			} else {
				vulnerability.Description = vulnerability.Description + " " + line
				continue
			}
		}

		// Try to parse the package that the vulnerability affects.
		affectsCaptureArr := affectsCaptureRegexp.FindAllStringSubmatch(line, -1)
		if len(affectsCaptureArr) > 0 {
			affectsCapture := affectsCaptureArr[0]

			md := map[string]string{}
			for i, n := range affectsCapture {
				md[affectsCaptureRegexpNames[i]] = strings.TrimSpace(n)
			}

			// Ignore Linux kernels.
			if strings.HasPrefix(md["package"], "linux") {
				continue
			}

			// Only consider the package if its status is needed, active, deferred, not-affected or
			// released. Ignore DNE (package does not exist), needs-triage, ignored, pending.
			if md["status"] == "needed" || md["status"] == "active" || md["status"] == "deferred" || md["status"] == "released" || md["status"] == "not-affected" {
				md["release"] = strings.Split(md["release"], "/")[0]
				if _, isReleaseIgnored := ubuntuIgnoredReleases[md["release"]]; isReleaseIgnored {
					continue
				}
				if _, isReleaseKnown := database.UbuntuReleasesMapping[md["release"]]; !isReleaseKnown {
					unknownReleases[md["release"]] = struct{}{}
					continue
				}

				var version string
				if md["status"] == "released" {
					if md["note"] != "" {
						var err error
						err = versionfmt.Valid(dpkg.ParserName, md["note"])
						if err != nil {
							log.WithError(err).WithField("version", md["note"]).Warning("could not parse package version. skipping")
						}
						version = md["note"]
					}
				} else {
					version = versionfmt.MaxVersion
				}
				if version == "" {
					continue
				}

				releaseName := "ubuntu:" + database.UbuntuReleasesMapping[md["release"]]
				if _, ok := uniqueRelease[releaseName+"_:_"+md["package"]]; ok {
					continue
				}

				uniqueRelease[releaseName+"_:_"+md["package"]] = struct{}{}
				var fixedinVersion string
				if version == versionfmt.MaxVersion {
					fixedinVersion = ""
				} else {
					fixedinVersion = version
				}

				// Create and add the new package.
				featureVersion := database.AffectedFeature{
					FeatureType: affectedType,
					Namespace: database.Namespace{
						Name:          releaseName,
						VersionFormat: dpkg.ParserName,
					},
					FeatureName:     md["package"],
					AffectedVersion: version,
					FixedInVersion:  fixedinVersion,
				}
				vulnerability.Affected = append(vulnerability.Affected, featureVersion)
			}
		}
	}

	// Trim extra spaces in the description
	vulnerability.Description = strings.TrimSpace(vulnerability.Description)

	// If no link has been provided (CVE-2006-NNN0 for instance), add the link to the tracker
	if vulnerability.Link == "" {
		vulnerability.Link = trackerURI
	}

	// If no priority has been provided (CVE-2007-0667 for instance), set the priority to Unknown
	if vulnerability.Severity == "" {
		vulnerability.Severity = database.UnknownSeverity
	}

	return
}

// SeverityFromPriority converts an priority from the Ubuntu CVE Tracker into
// a database.Severity.
func SeverityFromPriority(priority string) database.Severity {
	switch priority {
	case "untriaged":
		return database.UnknownSeverity
	case "negligible":
		return database.NegligibleSeverity
	case "low":
		return database.LowSeverity
	case "medium":
		return database.MediumSeverity
	case "high":
		return database.HighSeverity
	case "critical":
		return database.CriticalSeverity
	default:
		log.Warningf("could not determine a vulnerability severity from: %s", priority)
		return database.UnknownSeverity
	}
}
