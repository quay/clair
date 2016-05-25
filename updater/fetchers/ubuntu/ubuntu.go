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

package ubuntu

import (
	"bufio"
	"bytes"
	"errors"
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
	"github.com/coreos/pkg/capnslog"
)

const (
	trackerURI        = "https://launchpad.net/ubuntu-cve-tracker"
	trackerRepository = "https://launchpad.net/ubuntu-cve-tracker"
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

	log = capnslog.NewPackageLogger("github.com/coreos/clair", "updater/fetchers/ubuntu")

	// ErrFilesystem is returned when a fetcher fails to interact with the local filesystem.
	ErrFilesystem = errors.New("updater/fetchers: something went wrong when interacting with the fs")
)

// UbuntuFetcher implements updater.Fetcher and gets vulnerability updates from
// the Ubuntu CVE Tracker.
type UbuntuFetcher struct {
	repositoryLocalPath string
}

func init() {
	updater.RegisterFetcher("Ubuntu", &UbuntuFetcher{})
}

// FetchUpdate gets vulnerability updates from the Ubuntu CVE Tracker.
func (fetcher *UbuntuFetcher) FetchUpdate(datastore database.Datastore) (resp updater.FetcherResponse, err error) {
	log.Info("fetching Ubuntu vulnerabilities")

	// Check to see if the repository does not already exist.
	if _, pathExists := os.Stat(fetcher.repositoryLocalPath); fetcher.repositoryLocalPath == "" || os.IsNotExist(pathExists) {
		// Create a temporary folder and download the repository.
		p, err := ioutil.TempDir(os.TempDir(), "ubuntu-cve-tracker")
		if err != nil {
			return resp, ErrFilesystem
		}

		// bzr wants an empty target directory.
		fetcher.repositoryLocalPath = p + "/repository"

		// Create the new repository.
		err = createRepository(fetcher.repositoryLocalPath)
		if err != nil {
			return resp, err
		}
	} else {
		// Update the repository that's already on disk.
		err = updateRepository(fetcher.repositoryLocalPath)
		if err != nil {
			return resp, err
		}
	}

	// Get revision number.
	revisionNumber, err := getRevisionNumber(fetcher.repositoryLocalPath)
	if err != nil {
		return resp, err
	}

	// Get the latest revision number we successfully applied in the database.
	dbRevisionNumber, err := datastore.GetKeyValue("ubuntuUpdater")
	if err != nil {
		return resp, err
	}

	// Get the list of vulnerabilities that we have to update.
	modifiedCVE, err := collectModifiedVulnerabilities(revisionNumber, dbRevisionNumber, fetcher.repositoryLocalPath)
	if err != nil {
		return resp, err
	}

	notes := make(map[string]struct{})
	for cvePath := range modifiedCVE {
		// Open the CVE file.
		file, err := os.Open(fetcher.repositoryLocalPath + "/" + cvePath)
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
		log.Debug("no Ubuntu update")
		return modifiedCVE, nil
	}

	// Handle a database that needs upgrading.
	out, err := utils.Exec(repositoryLocalPath, "bzr", "log", "--verbose", "-r"+strconv.Itoa(dbRevisionInt+1)+"..", "-n0")
	if err != nil {
		log.Errorf("could not get Ubuntu vulnerabilities repository logs: %s. output: %s", err, out)
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

func createRepository(pathToRepo string) error {
	// Branch repository
	out, err := utils.Exec("/tmp/", "bzr", "branch", trackerRepository, pathToRepo)
	if err != nil {
		log.Errorf("could not branch Ubuntu repository: %s. output: %s", err, out)
		return cerrors.ErrCouldNotDownload
	}
	return nil
}

func updateRepository(pathToRepo string) error {
	// Pull repository
	out, err := utils.Exec(pathToRepo, "bzr", "pull", "--overwrite")
	if err != nil {
		log.Errorf("could not pull Ubuntu repository: %s. output: %s", err, out)
		return cerrors.ErrCouldNotDownload
	}
	return nil
}

func getRevisionNumber(pathToRepo string) (int, error) {
	out, err := utils.Exec(pathToRepo, "bzr", "revno")
	if err != nil {
		log.Errorf("could not get Ubuntu repository's revision number: %s. output: %s", err, out)
		return 0, cerrors.ErrCouldNotDownload
	}
	revno, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil {
		log.Errorf("could not parse Ubuntu repository's revision number: %s. output: %s", err, out)
		return 0, cerrors.ErrCouldNotDownload
	}
	return revno, nil
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

			vulnerability.Severity = ubuntuPriorityToSeverity(priority)
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
				} else if md["status"] == "not-affected" {
					version = types.MinVersion
				} else {
					version = types.MaxVersion
				}
				if version.String() == "" {
					continue
				}

				// Create and add the new package.
				featureVersion := database.FeatureVersion{
					Feature: database.Feature{
						Namespace: database.Namespace{Name: "ubuntu:" + database.UbuntuReleasesMapping[md["release"]]},
						Name:      md["package"],
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
		vulnerability.Severity = types.Unknown
	}

	return
}

func ubuntuPriorityToSeverity(priority string) types.Priority {
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

// Clean deletes any allocated resources.
func (fetcher *UbuntuFetcher) Clean() {
	if fetcher.repositoryLocalPath != "" {
		os.RemoveAll(fetcher.repositoryLocalPath)
	}
}
