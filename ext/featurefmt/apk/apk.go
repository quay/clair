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

	log "github.com/sirupsen/logrus"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/ext/featurefmt"
	"github.com/coreos/clair/ext/versionfmt"
	"github.com/coreos/clair/ext/versionfmt/dpkg"
	"github.com/coreos/clair/pkg/tarutil"
)

func init() {
	featurefmt.RegisterLister("apk", dpkg.ParserName, &lister{})
}

type lister struct{}

func (l lister) ListFeatures(files tarutil.FilesMap) ([]database.Feature, error) {
	file, exists := files["lib/apk/db/installed"]
	if !exists {
		return []database.Feature{}, nil
	}

	// Iterate over each line in the "installed" file attempting to parse each
	// package into a feature that will be stored in a set to guarantee
	// uniqueness.
	pkgSet := make(map[string]database.Feature)
	ipkg := database.Feature{}
	scanner := bufio.NewScanner(bytes.NewBuffer(file))
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) < 2 {
			continue
		}

		// Parse the package name or version.
		switch {
		case line[:2] == "P:":
			ipkg.Name = line[2:]
		case line[:2] == "V:":
			version := string(line[2:])
			err := versionfmt.Valid(dpkg.ParserName, version)
			if err != nil {
				log.WithError(err).WithField("version", version).Warning("could not parse package version. skipping")
			} else {
				ipkg.Version = version
			}
		case line == "":
			// Restart if the parser reaches another package definition before
			// creating a valid package.
			ipkg = database.Feature{}
		}

		// If we have a whole feature, store it in the set and try to parse a new
		// one.
		if ipkg.Name != "" && ipkg.Version != "" {
			pkgSet[ipkg.Name+"#"+ipkg.Version] = ipkg
			ipkg = database.Feature{}
		}
	}

	// Convert the map into a slice and attach the version format
	pkgs := make([]database.Feature, 0, len(pkgSet))
	for _, pkg := range pkgSet {
		pkg.VersionFormat = dpkg.ParserName
		pkgs = append(pkgs, pkg)
	}

	return pkgs, nil
}

func (l lister) RequiredFilenames() []string {
	return []string{"lib/apk/db/installed"}
}
