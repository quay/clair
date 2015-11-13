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

package fetchers

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/updater"
	"github.com/coreos/clair/utils"
	cerrors "github.com/coreos/clair/utils/errors"
	"github.com/coreos/clair/utils/types"
)

const (
	ubuntuTrackerURI  = "https://launchpad.net/ubuntu-cve-tracker"
	ubuntuTracker     = "lp:ubuntu-cve-tracker"
	ubuntuUpdaterFlag = "ubuntuUpdater"
)

var (
	repositoryLocalPath string

	ubuntuIgnoredReleases = map[string]struct{}{
		"upstream": struct{}{},
		"devel":    struct{}{},

		"dapper":   struct{}{},
		"edgy":     struct{}{},
		"feisty":   struct{}{},
		"gutsy":    struct{}{},
		"hardy":    struct{}{},
		"intrepid": struct{}{},
		"jaunty":   struct{}{},
		"karmic":   struct{}{},
		"lucid":    struct{}{},
		"maverick": struct{}{},
		"natty":    struct{}{},
		"oneiric":  struct{}{},
		"saucy":    struct{}{},

		// Syntax error
		"Patches": struct{}{},
		// Product
		"product": struct{}{},
	}

	branchedRegexp            = regexp.MustCompile(`Branched (\d+) revisions.`)
	revisionRegexp            = regexp.MustCompile(`Now on revision (\d+).`)
	affectsCaptureRegexp      = regexp.MustCompile(`(?P<release>.*)_(?P<package>.*): (?P<status>[^\s]*)( \(+(?P<note>[^()]*)\)+)?`)
	affectsCaptureRegexpNames = affectsCaptureRegexp.SubexpNames()
)

// UbuntuFetcher implements updater.Fetcher and get vulnerability updates from
// the Ubuntu CVE Tracker.
type UbuntuFetcher struct{}

func init() {
	updater.RegisterFetcher("Ubuntu", &UbuntuFetcher{})
}

// FetchUpdate gets vulnerability updates from the Ubuntu CVE Tracker.
func (fetcher *UbuntuFetcher) FetchUpdate() (resp updater.FetcherResponse, err error) {
	log.Info("fetching Ubuntu vulneratibilities")

	// Check to see if the repository does not already exist.
	var revisionNumber int
	if _, pathExists := os.Stat(repositoryLocalPath); repositoryLocalPath == "" || os.IsNotExist(pathExists) {
		// Create a temporary folder and download the repository.
		p, err := ioutil.TempDir(os.TempDir(), "ubuntu-cve-tracker")
		if err != nil {
			return resp, ErrFilesystem
		}

		// bzr wants an empty target directory.
		repositoryLocalPath = p + "/repository"

		// Create the new repository.
		revisionNumber, err = createRepository(repositoryLocalPath)
		if err != nil {
			return resp, err
		}
	} else {
		// Update the repository that's already on disk.
		revisionNumber, err = updateRepository(repositoryLocalPath)
		if err != nil {
			return resp, err
		}
	}

	// Get the latest revision number we successfully applied in the database.
	dbRevisionNumber, err := database.GetFlagValue("ubuntuUpdater")
	if err != nil {
		return resp, err
	}

	// Get the list of vulnerabilities that we have to update.
	modifiedCVE, err := collectModifiedVulnerabilities(revisionNumber, dbRevisionNumber, repositoryLocalPath)
	if err != nil {
		return resp, err
	}

	// Parse and add the vulnerabilities.
	for cvePath := range modifiedCVE {
		file, err := os.Open(repositoryLocalPath + "/" + cvePath)
		if err != nil {
			// This can happen when a file is modified and then moved in another
			// commit.
			continue
		}
		defer file.Close()

		v, unknownReleases, err := parseUbuntuCVE(file)
		if err != nil {
			return resp, err
		}

		if len(v.FixedIn) > 0 {
			resp.Vulnerabilities = append(resp.Vulnerabilities, v)
		}

		// Log any unknown releases.
		for k := range unknownReleases {
			note := fmt.Sprintf("Ubuntu %s is not mapped to any version number (eg. trusty->14.04). Please update me.", k)
			resp.Notes = append(resp.Notes, note)
			log.Warning(note)

			// If we encountered unknown Ubuntu release, we don't want the revision
			// number to be considered as managed.
			dbRevisionNumberInt, _ := strconv.Atoi(dbRevisionNumber)
			revisionNumber = dbRevisionNumberInt
		}
	}

	// Add flag information
	resp.FlagName = ubuntuUpdaterFlag
	resp.FlagValue = strconv.Itoa(revisionNumber)

	return
}

func collectModifiedVulnerabilities(revision int, dbRevision, repositoryLocalPath string) (map[string]struct{}, error) {
	modifiedCVE := make(map[string]struct{})

	// Handle a brand new database.
	if dbRevision == "" {
		for _, folder := range []string{"active", "retired"} {
			d, err := os.Open(repositoryLocalPath + "/" + folder)
			if err != nil {
				log.Errorf("could not open Ubuntu vulnerabilities repository's folder: %s", err)
				return nil, ErrFilesystem
			}
			defer d.Close()

			// Get the FileInfo of all the files in the directory.
			names, err := d.Readdirnames(-1)
			if err != nil {
				log.Errorf("could not read Ubuntu vulnerabilities repository's folder:: %s.", err)
				return nil, ErrFilesystem
			}

			// Add the vulnerabilities to the list.
			for _, name := range names {
				if strings.HasPrefix(name, "CVE-") {
					modifiedCVE[folder+"/"+name] = struct{}{}
				}
			}
		}

		return modifiedCVE, nil
	}

	// Handle an up to date database.
	dbRevisionInt, _ := strconv.Atoi(dbRevision)
	if revision == dbRevisionInt {
		log.Debug("no Ubuntu update")
		return modifiedCVE, nil
	}

	// Handle a database that needs upgrading.
	out, err := utils.Exec(repositoryLocalPath, "bzr", "log", "--verbose", "-r"+strconv.Itoa(dbRevisionInt+1)+"..", "-n0")
	if err != nil {
		log.Errorf("could not get Ubuntu vulnerabilities repository logs: %s. output: %s", err, string(out))
		return nil, cerrors.ErrCouldNotDownload
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

func createRepository(pathToRepo string) (int, error) {
	// Branch repository
	out, err := utils.Exec("/tmp/", "bzr", "branch", ubuntuTracker, pathToRepo)
	if err != nil {
		log.Errorf("could not branch Ubuntu repository: %s. output: %s", err, string(out))
		return 0, cerrors.ErrCouldNotDownload
	}

	// Get revision number
	regexpMatches := branchedRegexp.FindStringSubmatch(string(out))
	if len(regexpMatches) != 2 {
		log.Error("could not parse bzr branch output to get the revision number")
		return 0, cerrors.ErrCouldNotDownload
	}

	revision, err := strconv.Atoi(regexpMatches[1])
	if err != nil {
		log.Error("could not parse bzr branch output to get the revision number")
		return 0, cerrors.ErrCouldNotDownload
	}

	return revision, err
}

func updateRepository(pathToRepo string) (int, error) {
	// Pull repository
	out, err := utils.Exec(pathToRepo, "bzr", "pull", "--overwrite")
	if err != nil {
		log.Errorf("could not pull Ubuntu repository: %s. output: %s", err, string(out))
		return 0, cerrors.ErrCouldNotDownload
	}

	// Get revision number
	if strings.Contains(string(out), "No revisions or tags to pull") {
		out, _ = utils.Exec(pathToRepo, "bzr", "revno")
		revno, err := strconv.Atoi(string(out[:len(out)-1]))
		if err != nil {
			log.Errorf("could not parse Ubuntu repository revision number: %s. output: %s", err, string(out))
			return 0, cerrors.ErrCouldNotDownload
		}
		return revno, nil
	}

	regexpMatches := revisionRegexp.FindStringSubmatch(string(out))
	if len(regexpMatches) != 2 {
		log.Error("could not parse bzr pull output to get the revision number")
		return 0, cerrors.ErrCouldNotDownload
	}

	revno, err := strconv.Atoi(regexpMatches[1])
	if err != nil {
		log.Error("could not parse bzr pull output to get the revision number")
		return 0, cerrors.ErrCouldNotDownload
	}

	return revno, nil
}

func parseUbuntuCVE(fileContent io.Reader) (vulnerability updater.FetcherVulnerability, unknownReleases map[string]struct{}, err error) {
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
			vulnerability.ID = strings.TrimSpace(strings.TrimPrefix(line, "Candidate:"))
			continue
		}

		// Parse the link.
		if vulnerability.Link == "" && strings.HasPrefix(line, "http") {
			vulnerability.Link = strings.TrimSpace(line)
			continue
		}

		// Parse the priority.
		if strings.HasPrefix(line, "Priority:") {
			priority := strings.TrimSpace(strings.TrimPrefix(line, "Priority:"))

			// Handle syntax error: Priority: medium (heap-protector)
			if strings.Contains(priority, " ") {
				priority = priority[:strings.Index(priority, " ")]
			}

			vulnerability.Priority = ubuntuPriorityToPriority(priority)
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

			// Only consider the package if its status is needed, active, deferred
			// or released. Ignore DNE, needs-triage, not-affected, ignored, pending.
			if md["status"] == "needed" || md["status"] == "active" || md["status"] == "deferred" || md["status"] == "released" {
				if _, isReleaseIgnored := ubuntuIgnoredReleases[md["release"]]; isReleaseIgnored {
					continue
				}
				if _, isReleaseKnown := database.UbuntuReleasesMapping[md["release"]]; !isReleaseKnown {
					unknownReleases[md["release"]] = struct{}{}
					continue
				}

				var version types.Version
				if md["status"] == "released" {
					if md["note"] != "" {
						var err error
						version, err = types.NewVersion(md["note"])
						if err != nil {
							log.Warningf("could not parse package version '%s': %s. skipping", md["note"], err)
						}
					}
				} else {
					version = types.MaxVersion
				}
				if version.String() == "" {
					continue
				}

				// Create and add the new package.
				vulnerability.FixedIn = append(vulnerability.FixedIn, &database.Package{OS: "ubuntu:" + database.UbuntuReleasesMapping[md["release"]], Name: md["package"], Version: version})
			}
		}
	}

	// Trim extra spaces in the description
	vulnerability.Description = strings.TrimSpace(vulnerability.Description)

	// If no link has been provided (CVE-2006-NNN0 for instance), add the link to the tracker
	if vulnerability.Link == "" {
		vulnerability.Link = ubuntuTrackerURI
	}

	// If no priority has been provided (CVE-2007-0667 for instance), set the priority to Unknown
	if vulnerability.Priority == "" {
		vulnerability.Priority = types.Unknown
	}

	return
}

func ubuntuPriorityToPriority(priority string) types.Priority {
	switch priority {
	case "untriaged":
		return types.Unknown
	case "negligible":
		return types.Negligible
	case "low":
		return types.Low
	case "medium":
		return types.Medium
	case "high":
		return types.High
	case "critical":
		return types.Critical
	}

	log.Warning("Could not determine a vulnerability priority from: %s", priority)
	return types.Unknown
}
