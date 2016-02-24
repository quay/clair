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

package rpm

import (
	"bufio"
	"io/ioutil"
	"os"
	"strings"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/utils"
	cerrors "github.com/coreos/clair/utils/errors"
	"github.com/coreos/clair/utils/types"
	"github.com/coreos/clair/worker/detectors"
	"github.com/coreos/pkg/capnslog"
)

var log = capnslog.NewPackageLogger("github.com/coreos/clair", "rpm")

// RpmFeaturesDetector implements FeaturesDetector and detects rpm packages
// It requires the "rpm" binary to be in the PATH
type RpmFeaturesDetector struct{}

func init() {
	detectors.RegisterFeaturesDetector("rpm", &RpmFeaturesDetector{})
}

// Detect detects packages using var/lib/rpm/Packages from the input data
func (detector *RpmFeaturesDetector) Detect(data map[string][]byte) ([]database.FeatureVersion, error) {
	f, hasFile := data["var/lib/rpm/Packages"]
	if !hasFile {
		return []database.FeatureVersion{}, nil
	}

	// Create a map to store packages and ensure their uniqueness
	packagesMap := make(map[string]database.FeatureVersion)

	// Write the required "Packages" file to disk
	tmpDir, err := ioutil.TempDir(os.TempDir(), "rpm")
	defer os.RemoveAll(tmpDir)
	if err != nil {
		log.Errorf("could not create temporary folder for RPM detection: %s", err)
		return []database.FeatureVersion{}, cerrors.ErrFilesystem
	}

	err = ioutil.WriteFile(tmpDir+"/Packages", f, 0700)
	if err != nil {
		log.Errorf("could not create temporary file for RPM detection: %s", err)
		return []database.FeatureVersion{}, cerrors.ErrFilesystem
	}

	// Query RPM
	// We actually extract binary package names instead of source package names here because RHSA refers to package names
	// In the dpkg system, we extract the source instead
	out, err := utils.Exec(tmpDir, "rpm", "--dbpath", tmpDir, "-qa", "--qf", "%{NAME} %{EPOCH}:%{VERSION}-%{RELEASE}\n")
	if err != nil {
		log.Errorf("could not query RPM: %s. output: %s", err, string(out))
		// Do not bubble up because we probably won't be able to fix it,
		// the database must be corrupted
		return []database.FeatureVersion{}, nil
	}

	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := strings.Split(scanner.Text(), " ")
		if len(line) != 2 {
			// We may see warnings on some RPM versions:
			// "warning: Generating 12 missing index(es), please wait..."
			continue
		}

		// Ignore gpg-pubkey packages which are fake packages used to store GPG keys - they are not versionned properly.
		if line[0] == "gpg-pubkey" {
			continue
		}

		// Parse version
		version, err := types.NewVersion(strings.Replace(line[1], "(none):", "", -1))
		if err != nil {
			log.Warningf("could not parse package version '%s': %s. skipping", line[1], err.Error())
			continue
		}

		// Add package
		pkg := database.FeatureVersion{
			Feature: database.Feature{
				Name: line[0],
			},
			Version: version,
		}
		packagesMap[pkg.Feature.Name+"#"+pkg.Version.String()] = pkg
	}

	// Convert the map to a slice
	packages := make([]database.FeatureVersion, 0, len(packagesMap))
	for _, pkg := range packagesMap {
		packages = append(packages, pkg)
	}

	return packages, nil
}

// GetRequiredFiles returns the list of files required for Detect, without
// leading /
func (detector *RpmFeaturesDetector) GetRequiredFiles() []string {
	return []string{"var/lib/rpm/Packages"}
}
