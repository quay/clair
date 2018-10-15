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

	"github.com/deckarep/golang-set"
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
	featurefmt.RegisterLister("dpkg", "1.0", &lister{})
}

func valid(pkg *database.Feature) bool {
	return pkg.Name != "" && pkg.Version != ""
}

func addSourcePackage(pkg *database.Feature) {
	if pkg.SourceName == "" {
		pkg.SourceName = pkg.Name
	}

	if pkg.SourceVersion == "" {
		pkg.SourceVersion = pkg.Version
	}
}

func (l lister) ListFeatures(files tarutil.FilesMap) ([]database.Feature, error) {
	f, hasFile := files["var/lib/dpkg/status"]
	if !hasFile {
		return []database.Feature{}, nil
	}

	var (
		pkg  = database.Feature{VersionFormat: dpkg.ParserName}
		pkgs = mapset.NewSet()
		err  error
	)

	scanner := bufio.NewScanner(strings.NewReader(string(f)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "Package: ") {
			// Package line
			// Defines the name of the package

			pkg.Name = strings.TrimSpace(strings.TrimPrefix(line, "Package: "))
			pkg.Version = ""
		} else if strings.HasPrefix(line, "Source: ") {
			// Source line (Optional)
			// Gives the name of the source package
			// May also specifies a version

			srcCapture := dpkgSrcCaptureRegexp.FindAllStringSubmatch(line, -1)[0]
			md := map[string]string{}
			for i, n := range srcCapture {
				md[dpkgSrcCaptureRegexpNames[i]] = strings.TrimSpace(n)
			}

			pkg.SourceName = md["name"]
			if md["version"] != "" {
				version := md["version"]
				if err = versionfmt.Valid(dpkg.ParserName, version); err != nil {
					log.WithError(err).WithField("version", string(line[1])).Warning("could not parse package version. skipping")
				} else {
					pkg.SourceVersion = version
				}
			}
		} else if strings.HasPrefix(line, "Version: ") {
			// Version line
			// Defines the version of the package
			// This version is less important than a version retrieved from a Source line
			// because the Debian vulnerabilities often skips the epoch from the Version field
			// which is not present in the Source version, and because +bX revisions don't matter
			version := strings.TrimPrefix(line, "Version: ")
			if err = versionfmt.Valid(dpkg.ParserName, version); err != nil {
				log.WithError(err).WithField("version", string(line[1])).Warning("could not parse package version. skipping")
			} else {
				pkg.Version = version
			}
		} else if line == "" {
			pkg = database.Feature{VersionFormat: dpkg.ParserName}
		}

		if valid(&pkg) {
			addSourcePackage(&pkg)
			pkgs.Add(pkg)
		}
	}

	return database.ConvertFeatureSetToFeatures(pkgs), nil
}

func (l lister) RequiredFilenames() []string {
	return []string{"var/lib/dpkg/status"}
}
