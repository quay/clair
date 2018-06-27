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

// Package ubuntu implements a vulnerability source updater using the
// Ubuntu CVE Tracker.
package ubuntu

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/ext/versionfmt"
	"github.com/coreos/clair/ext/versionfmt/dpkg"
	"github.com/coreos/clair/ext/vulnsrc"
	"github.com/coreos/clair/pkg/commonerr"
)

const (
	trackerURI        = "https://launchpad.net/~ubuntu-security/ubuntu-cve-tracker/master"
	trackerRepository = "https://launchpad.net/~ubuntu-security/ubuntu-cve-tracker/master"
	updaterFlag       = "ubuntuUpdater"
	cveURL            = "http://people.ubuntu.com/~ubuntu-security/cve/%s"
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
)

type updater struct {
	repositoryLocalPath string
}

func init() {
	vulnsrc.RegisterUpdater("ubuntu", &updater{})
}

func (u *updater) Update(datastore database.Datastore) (resp vulnsrc.UpdateResponse, err error) {
	log.WithField("package", "Ubuntu").Info("Start fetching vulnerabilities")

	// Pull the bzr repository.
	if err = u.pullRepository(); err != nil {
		return resp, err
	}

	// Get revision number.
	revisionNumber, err := getRevisionNumber(u.repositoryLocalPath)
	if err != nil {
		return resp, err
	}

	// Get the latest revision number we successfully applied in the database.
	dbRevisionNumber, err := datastore.GetKeyValue("ubuntuUpdater")
	if err != nil {
		return resp, err
	}

	// Get the list of vulnerabilities that we have to update.
	modifiedCVE, err := collectModifiedVulnerabilities(revisionNumber, dbRevisionNumber, u.repositoryLocalPath)
	if err != nil {
		return resp, err
	}

	notes := make(map[string]struct{})
	for cvePath := range modifiedCVE {
		// Open the CVE file.
		file, err := os.Open(u.repositoryLocalPath + "/" + cvePath)
		if err != nil {
			// This can happen when a file is modified and then moved in another
			// commit.
			continue
		}

		// Parse the vulnerability.
		v, unknownReleases, err := parseUbuntuCVE(file)
		if err != nil {
			return resp, err
		}

		// Add the vulnerability to the response.
		resp.Vulnerabilities = append(resp.Vulnerabilities, v)

		// Store any unknown releases as notes.
		for k := range unknownReleases {
			note := fmt.Sprintf("Ubuntu %s is not mapped to any version number (eg. trusty->14.04). Please update me.", k)
			notes[note] = struct{}{}

			// If we encountered unknown Ubuntu release, we don't want the revision
			// number to be considered as managed.
			dbRevisionNumberInt, _ := strconv.Atoi(dbRevisionNumber)
			revisionNumber = dbRevisionNumberInt
		}

		// Close the file manually.
		//
		// We do that instead of using defer because defer works on a function-level scope.
		// We would open many files and close them all at once at the end of the function,
		// which could lead to exceed fs.file-max.
		file.Close()
	}

	// Add flag and notes.
	resp.FlagName = updaterFlag
	resp.FlagValue = strconv.Itoa(revisionNumber)
	for note := range notes {
		resp.Notes = append(resp.Notes, note)
	}

	return
}

func (u *updater) Clean() {
	os.RemoveAll(u.repositoryLocalPath)
}

func (u *updater) pullRepository() (err error) {
	// Determine whether we should branch or pull.
	if _, pathExists := os.Stat(u.repositoryLocalPath); u.repositoryLocalPath == "" || os.IsNotExist(pathExists) {
		// Create a temporary folder to store the repository.
		if u.repositoryLocalPath, err = ioutil.TempDir(os.TempDir(), "ubuntu-cve-tracker"); err != nil {
			return vulnsrc.ErrFilesystem
		}

		// Branch repository.
		cmd := exec.Command("bzr", "branch", "--use-existing-dir", trackerRepository, ".")
		cmd.Dir = u.repositoryLocalPath
		if out, err := cmd.CombinedOutput(); err != nil {
			log.WithError(err).WithField("output", string(out)).Error("could not branch Ubuntu repository")
			return commonerr.ErrCouldNotDownload
		}

		return nil
	}

	// Pull repository.
	cmd := exec.Command("bzr", "pull", "--overwrite")
	cmd.Dir = u.repositoryLocalPath
	if out, err := cmd.CombinedOutput(); err != nil {
		os.RemoveAll(u.repositoryLocalPath)
		log.WithError(err).WithField("output", string(out)).Error("could not pull Ubuntu repository")
		return commonerr.ErrCouldNotDownload
	}

	return nil
}

func getRevisionNumber(pathToRepo string) (int, error) {
	cmd := exec.Command("bzr", "revno")
	cmd.Dir = pathToRepo
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.WithError(err).WithField("output", string(out)).Error("could not get Ubuntu repository's revision number")
		return 0, commonerr.ErrCouldNotDownload
	}

	revno, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil {
		log.WithError(err).WithField("output", string(out)).Error("could not parse Ubuntu repository's revision number")
		return 0, commonerr.ErrCouldNotDownload
	}

	return revno, nil
}

func collectModifiedVulnerabilities(revision int, dbRevision, repositoryLocalPath string) (map[string]struct{}, error) {
	modifiedCVE := make(map[string]struct{})

	// Handle a brand new database.
	if dbRevision == "" {
		for _, folder := range []string{"active", "retired"} {
			d, err := os.Open(repositoryLocalPath + "/" + folder)
			if err != nil {
				log.WithError(err).Error("could not open Ubuntu vulnerabilities repository's folder")
				return nil, vulnsrc.ErrFilesystem
			}

			// Get the FileInfo of all the files in the directory.
			names, err := d.Readdirnames(-1)
			if err != nil {
				log.WithError(err).Error("could not read Ubuntu vulnerabilities repository's folder")
				return nil, vulnsrc.ErrFilesystem
			}

			// Add the vulnerabilities to the list.
			for _, name := range names {
				if strings.HasPrefix(name, "CVE-") {
					modifiedCVE[folder+"/"+name] = struct{}{}
				}
			}

			// Close the file manually.
			//
			// We do that instead of using defer because defer works on a function-level scope.
			// We would open many files and close them all at once at the end of the function,
			// which could lead to exceed fs.file-max.
			d.Close()
		}

		return modifiedCVE, nil
	}

	// Handle an up to date database.
	dbRevisionInt, _ := strconv.Atoi(dbRevision)
	if revision == dbRevisionInt {
		log.WithField("package", "Ubuntu").Debug("no update")
		return modifiedCVE, nil
	}

	// Handle a database that needs upgrading.
	cmd := exec.Command("bzr", "log", "--verbose", "-r"+strconv.Itoa(dbRevisionInt+1)+"..", "-n0")
	cmd.Dir = repositoryLocalPath
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.WithError(err).WithField("output", string(out)).Error("could not get Ubuntu vulnerabilities repository logs")
		return nil, commonerr.ErrCouldNotDownload
	}

	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		text := strings.TrimSpace(scanner.Text())
		if strings.Contains(text, "CVE-") && (strings.HasPrefix(text, "active/") || strings.HasPrefix(text, "retired/")) {
			if strings.Contains(text, " => ") {
				text = text[strings.Index(text, " => ")+4:]
			}
			modifiedCVE[text] = struct{}{}
		}
	}

	return modifiedCVE, nil
}

func parseUbuntuCVE(fileContent io.Reader) (vulnerability database.Vulnerability, unknownReleases map[string]struct{}, err error) {
	unknownReleases = make(map[string]struct{})
	readingDescription := false
	scanner := bufio.NewScanner(fileContent)

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
				} else if md["status"] == "not-affected" {
					version = versionfmt.MinVersion
				} else {
					version = versionfmt.MaxVersion
				}
				if version == "" {
					continue
				}

				// Create and add the new package.
				featureVersion := database.FeatureVersion{
					Feature: database.Feature{
						Namespace: database.Namespace{
							Name:          "ubuntu:" + database.UbuntuReleasesMapping[md["release"]],
							VersionFormat: dpkg.ParserName,
						},
						Name: md["package"],
					},
					Version: version,
				}
				vulnerability.FixedIn = append(vulnerability.FixedIn, featureVersion)
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
		log.Warning("could not determine a vulnerability severity from: %s", priority)
		return database.UnknownSeverity
	}
}
