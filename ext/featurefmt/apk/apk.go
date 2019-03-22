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

// Package apk implements a featurefmt.Lister for APK packages.
package apk

import (
	"bufio"
	"bytes"

	"github.com/deckarep/golang-set"
	log "github.com/sirupsen/logrus"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/ext/featurefmt"
	"github.com/coreos/clair/ext/versionfmt"
	"github.com/coreos/clair/ext/versionfmt/dpkg"
	"github.com/coreos/clair/pkg/tarutil"
)

func init() {
	featurefmt.RegisterLister("apk", "1.0", &lister{})
}

type lister struct{}

func valid(pkg *database.Feature) bool {
	return pkg.Name != "" && pkg.Version != ""
}

func (l lister) ListFeatures(files tarutil.FilesMap) ([]database.LayerFeature, error) {
	file, exists := files["lib/apk/db/installed"]
	if !exists {
		return []database.LayerFeature{}, nil
	}

	// Iterate over each line in the "installed" file attempting to parse each
	// package into a feature that will be stored in a set to guarantee
	// uniqueness.
	packages := mapset.NewSet()
	pkg := database.Feature{VersionFormat: dpkg.ParserName}
	scanner := bufio.NewScanner(bytes.NewBuffer(file))
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) < 2 {
			if valid(&pkg) {
				pkg.Type = database.BinaryPackage
				packages.Add(pkg)
				pkg = database.Feature{VersionFormat: dpkg.ParserName}
			}
			continue
		}

		// Parse the package name or version.
		// Alpine package doesn't have specific source package. The "origin"
		// package is sub package.
		switch line[:2] {
		case "P:":
			pkg.Name = line[2:]
		case "V:":
			version := string(line[2:])
			err := versionfmt.Valid(dpkg.ParserName, version)
			if err != nil {
				log.WithError(err).WithField("version", version).Warning("could not parse package version. skipping")
				continue
			} else {
				pkg.Version = version
			}
		}
	}

	// in case of no terminal line
	if valid(&pkg) {
		pkg.Type = database.BinaryPackage
		packages.Add(pkg)
	}

	return database.ConvertFeatureSetToLayerFeatures(packages), nil
}

func (l lister) RequiredFilenames() []string {
	return []string{"^lib/apk/db/installed"}
}
