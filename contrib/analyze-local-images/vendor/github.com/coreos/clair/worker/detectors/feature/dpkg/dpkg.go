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

package dpkg

import (
	"bufio"
	"regexp"
	"strings"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/utils/types"
	"github.com/coreos/clair/worker/detectors"
	"github.com/coreos/pkg/capnslog"
)

var (
	log = capnslog.NewPackageLogger("github.com/coreos/clair", "worker/detectors/packages")

	dpkgSrcCaptureRegexp      = regexp.MustCompile(`Source: (?P<name>[^\s]*)( \((?P<version>.*)\))?`)
	dpkgSrcCaptureRegexpNames = dpkgSrcCaptureRegexp.SubexpNames()
)

// DpkgFeaturesDetector implements FeaturesDetector and detects dpkg packages
type DpkgFeaturesDetector struct{}

func init() {
	detectors.RegisterFeaturesDetector("dpkg", &DpkgFeaturesDetector{})
}

// Detect detects packages using var/lib/dpkg/status from the input data
func (detector *DpkgFeaturesDetector) Detect(data map[string][]byte) ([]database.FeatureVersion, error) {
	f, hasFile := data["var/lib/dpkg/status"]
	if !hasFile {
		return []database.FeatureVersion{}, nil
	}

	// Create a map to store packages and ensure their uniqueness
	packagesMap := make(map[string]database.FeatureVersion)

	var pkg database.FeatureVersion
	var err error
	scanner := bufio.NewScanner(strings.NewReader(string(f)))
	for scanner.Scan() {
		line := scanner.Text()

		if strings.HasPrefix(line, "Package: ") {
			// Package line
			// Defines the name of the package

			pkg.Feature.Name = strings.TrimSpace(strings.TrimPrefix(line, "Package: "))
			pkg.Version = types.Version{}
		} else if strings.HasPrefix(line, "Source: ") {
			// Source line (Optionnal)
			// Gives the name of the source package
			// May also specifies a version

			srcCapture := dpkgSrcCaptureRegexp.FindAllStringSubmatch(line, -1)[0]
			md := map[string]string{}
			for i, n := range srcCapture {
				md[dpkgSrcCaptureRegexpNames[i]] = strings.TrimSpace(n)
			}

			pkg.Feature.Name = md["name"]
			if md["version"] != "" {
				pkg.Version, err = types.NewVersion(md["version"])
				if err != nil {
					log.Warningf("could not parse package version '%s': %s. skipping", line[1], err.Error())
				}
			}
		} else if strings.HasPrefix(line, "Version: ") && pkg.Version.String() == "" {
			// Version line
			// Defines the version of the package
			// This version is less important than a version retrieved from a Source line
			// because the Debian vulnerabilities often skips the epoch from the Version field
			// which is not present in the Source version, and because +bX revisions don't matter
			pkg.Version, err = types.NewVersion(strings.TrimPrefix(line, "Version: "))
			if err != nil {
				log.Warningf("could not parse package version '%s': %s. skipping", line[1], err.Error())
			}
		}

		// Add the package to the result array if we have all the informations
		if pkg.Feature.Name != "" && pkg.Version.String() != "" {
			packagesMap[pkg.Feature.Name+"#"+pkg.Version.String()] = pkg
			pkg.Feature.Name = ""
			pkg.Version = types.Version{}
		}
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
func (detector *DpkgFeaturesDetector) GetRequiredFiles() []string {
	return []string{"var/lib/dpkg/status"}
}
