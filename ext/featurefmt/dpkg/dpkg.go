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

// Package dpkg implements a featurefmt.Lister for dpkg packages.
package dpkg

import (
	"bufio"
	"regexp"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/ext/featurefmt"
	"github.com/coreos/clair/ext/versionfmt"
	"github.com/coreos/clair/ext/versionfmt/dpkg"
	"github.com/coreos/clair/pkg/tarutil"
)

var (
	dpkgSrcCaptureRegexp      = regexp.MustCompile(`Source: (?P<name>[^\s]*)( \((?P<version>.*)\))?`)
	dpkgSrcCaptureRegexpNames = dpkgSrcCaptureRegexp.SubexpNames()
)

type lister struct{}

func init() {
	featurefmt.RegisterLister("dpkg", &lister{})
}

func (l lister) ListFeatures(files tarutil.FilesMap) ([]database.FeatureVersion, error) {
	f, hasFile := files["var/lib/dpkg/status"]
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
			pkg.Version = ""
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
				version := md["version"]
				err = versionfmt.Valid(dpkg.ParserName, version)
				if err != nil {
					log.WithError(err).WithField("version", string(line[1])).Warning("could not parse package version. skipping")
				} else {
					pkg.Version = version
				}
			}
		} else if strings.HasPrefix(line, "Version: ") && pkg.Version == "" {
			// Version line
			// Defines the version of the package
			// This version is less important than a version retrieved from a Source line
			// because the Debian vulnerabilities often skips the epoch from the Version field
			// which is not present in the Source version, and because +bX revisions don't matter
			version := strings.TrimPrefix(line, "Version: ")
			err = versionfmt.Valid(dpkg.ParserName, version)
			if err != nil {
				log.WithError(err).WithField("version", string(line[1])).Warning("could not parse package version. skipping")
			} else {
				pkg.Version = version
			}
		} else if line == "" {
			pkg.Feature.Name = ""
			pkg.Version = ""
		}

		// Add the package to the result array if we have all the informations
		if pkg.Feature.Name != "" && pkg.Version != "" {
			packagesMap[pkg.Feature.Name+"#"+pkg.Version] = pkg
			pkg.Feature.Name = ""
			pkg.Version = ""
		}
	}

	// Convert the map to a slice
	packages := make([]database.FeatureVersion, 0, len(packagesMap))
	for _, pkg := range packagesMap {
		packages = append(packages, pkg)
	}

	return packages, nil
}

func (l lister) RequiredFilenames() []string {
	return []string{"var/lib/dpkg/status"}
}
