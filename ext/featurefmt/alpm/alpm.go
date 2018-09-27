// Copyright 2017-2018 clair authors
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

// Package alpm implements a featurefmt.Lister for ALPM packages.
package alpm

import (
	"bufio"
	"bytes"

	log "github.com/sirupsen/logrus"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/ext/featurefmt"
	"github.com/coreos/clair/ext/versionfmt"
	"github.com/coreos/clair/ext/versionfmt/rpm"
	"github.com/coreos/clair/pkg/tarutil"

	"strings"
)

func init() {
	featurefmt.RegisterLister("alpm", rpm.ParserName, &lister{})
}

type lister struct{}

func (l lister) ListFeatures(files tarutil.FilesMap) ([]database.Feature, error) {
	pkgSet := make(map[string]database.Feature)
	alpm := database.Feature{}
	for name, file := range files {
		if !strings.HasSuffix(name, "desc") {
			continue
		}
		nameLabel := false
		versionLabel := false
		scanner := bufio.NewScanner(bytes.NewBuffer(file))
		for scanner.Scan() {
			line := scanner.Text()

			switch {
			case line == "%NAME%":
				nameLabel = true
			case nameLabel:
				alpm.Name = line
				nameLabel = false
			case line == "%VERSION%":
				versionLabel = true
			case versionLabel:
				err := versionfmt.Valid(rpm.ParserName, line)
				if err != nil {
					log.WithError(err).WithField("version", line).Warning("could not parse package version. skipping")
				} else {
					alpm.Version = line
				}
				versionLabel = false
			}

			if alpm.Name != "" && alpm.Version != "" {
				pkgSet[alpm.Name+"#"+alpm.Version] = alpm
				alpm = database.Feature{}
				// No need to continue reading the file at this point
				break
			}
		}
	}

	// Convert the map into a slice and attach the version format
	pkgs := make([]database.Feature, 0, len(pkgSet))
	for _, pkg := range pkgSet {
		pkg.VersionFormat = rpm.ParserName
		pkgs = append(pkgs, pkg)
	}

	return pkgs, nil
}

func (l lister) RequiredFilenames() []string {
	return []string{"var/lib/pacman/local/"}
}
