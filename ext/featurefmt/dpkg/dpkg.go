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

func (l lister) RequiredFilenames() []string {
	return []string{"^var/lib/dpkg/status"}
}

func init() {
	featurefmt.RegisterLister("dpkg", "1.0", &lister{})
}

func (l lister) ListFeatures(files tarutil.FilesMap) ([]database.LayerFeature, error) {
	f, hasFile := files["var/lib/dpkg/status"]
	if !hasFile {
		return []database.LayerFeature{}, nil
	}

	packages := mapset.NewSet()
	scanner := bufio.NewScanner(strings.NewReader(string(f)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		binary, source := parseDpkgDB(scanner)
		if binary != nil {
			packages.Add(*binary)
		}

		if source != nil {
			packages.Add(*source)
		}
	}

	return database.ConvertFeatureSetToLayerFeatures(packages), nil
}

// parseDpkgDB consumes the status file scanner exactly one package info, until
// EOF or empty space, and generate the parsed packages from it.
func parseDpkgDB(scanner *bufio.Scanner) (binaryPackage *database.Feature, sourcePackage *database.Feature) {
	var (
		name          string
		version       string
		sourceName    string
		sourceVersion string
	)

	for {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			break
		}

		if strings.HasPrefix(line, "Package: ") {
			name = strings.TrimSpace(strings.TrimPrefix(line, "Package: "))
		} else if strings.HasPrefix(line, "Source: ") {
			// Source line (Optional)
			// Gives the name of the source package
			// May also specifies a version

			srcCapture := dpkgSrcCaptureRegexp.FindAllStringSubmatch(line, -1)[0]
			md := map[string]string{}
			for i, n := range srcCapture {
				md[dpkgSrcCaptureRegexpNames[i]] = strings.TrimSpace(n)
			}

			sourceName = md["name"]
			if md["version"] != "" {
				sourceVersion = md["version"]
			}
		} else if strings.HasPrefix(line, "Version: ") {
			// Version line
			// Defines the version of the package
			// This version is less important than a version retrieved from a Source line
			// because the Debian vulnerabilities often skips the epoch from the Version field
			// which is not present in the Source version, and because +bX revisions don't matter
			version = strings.TrimPrefix(line, "Version: ")
		}

		if !scanner.Scan() {
			break
		}
	}

	if name != "" && version != "" {
		if err := versionfmt.Valid(dpkg.ParserName, version); err != nil {
			log.WithError(err).WithFields(log.Fields{"name": name, "version": version}).Warning("skipped unparseable package")
		} else {
			binaryPackage = &database.Feature{name, version, dpkg.ParserName, database.BinaryPackage}
		}
	}

	// Source version and names are computed from binary package names and versions
	// in dpkg.
	// Source package name:
	// https://git.dpkg.org/cgit/dpkg/dpkg.git/tree/lib/dpkg/pkg-format.c#n338
	// Source package version:
	// https://git.dpkg.org/cgit/dpkg/dpkg.git/tree/lib/dpkg/pkg-format.c#n355
	if sourceName == "" {
		sourceName = name
	}

	if sourceVersion == "" {
		sourceVersion = version
	}

	if sourceName != "" && sourceVersion != "" {
		if err := versionfmt.Valid(dpkg.ParserName, version); err != nil {
			log.WithError(err).WithFields(log.Fields{"name": name, "version": version}).Warning("skipped unparseable package")
		} else {
			sourcePackage = &database.Feature{sourceName, sourceVersion, dpkg.ParserName, database.SourcePackage}
		}
	}

	return
}
