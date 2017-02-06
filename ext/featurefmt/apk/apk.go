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

	"github.com/coreos/pkg/capnslog"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/ext/featurefmt"
	"github.com/coreos/clair/ext/versionfmt"
	"github.com/coreos/clair/ext/versionfmt/dpkg"
	"github.com/coreos/clair/pkg/tarutil"
)

var log = capnslog.NewPackageLogger("github.com/coreos/clair", "ext/featurefmt/apk")

func init() {
	featurefmt.RegisterLister("apk", &lister{})
}

type lister struct{}

func (l lister) ListFeatures(files tarutil.FilesMap) ([]database.FeatureVersion, error) {
	file, exists := files["lib/apk/db/installed"]
	if !exists {
		return []database.FeatureVersion{}, nil
	}

	// Iterate over each line in the "installed" file attempting to parse each
	// package into a feature that will be stored in a set to guarantee
	// uniqueness.
	pkgSet := make(map[string]database.FeatureVersion)
	ipkg := database.FeatureVersion{}
	scanner := bufio.NewScanner(bytes.NewBuffer(file))
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) < 2 {
			continue
		}

		// Parse the package name or version.
		switch {
		case line[:2] == "P:":
			ipkg.Feature.Name = line[2:]
		case line[:2] == "V:":
			version := string(line[2:])
			err := versionfmt.Valid(dpkg.ParserName, version)
			if err != nil {
				log.Warningf("could not parse package version '%s': %s. skipping", version, err.Error())
			} else {
				ipkg.Version = version
			}
		}

		// If we have a whole feature, store it in the set and try to parse a new
		// one.
		if ipkg.Feature.Name != "" && ipkg.Version != "" {
			pkgSet[ipkg.Feature.Name+"#"+ipkg.Version] = ipkg
			ipkg = database.FeatureVersion{}
		}
	}

	// Convert the map into a slice.
	pkgs := make([]database.FeatureVersion, 0, len(pkgSet))
	for _, pkg := range pkgSet {
		pkgs = append(pkgs, pkg)
	}

	return pkgs, nil
}

func (l lister) RequiredFilenames() []string {
	return []string{"lib/apk/db/installed"}
}
