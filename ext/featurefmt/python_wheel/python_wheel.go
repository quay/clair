// Copyright 2019 clair authors
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

// This package implements a featurefmt.Lister for discovering any JavaScript
// packages installed through NPM
package python_wheel

import (
	"bufio"
	"bytes"
	"github.com/coreos/clair/database"
	"github.com/coreos/clair/ext/featurefmt"
	"github.com/coreos/clair/ext/versionfmt"
	"github.com/coreos/clair/ext/versionfmt/pep440"
	"github.com/coreos/clair/pkg/tarutil"
	"github.com/deckarep/golang-set"
	log "github.com/sirupsen/logrus"
	"strings"
)

type metadata struct {
	Name    string
	Version string
}

type lister struct{}

func (lister) ListFeatures(files tarutil.FilesMap) ([]database.LayerFeature, error) {
	packages := mapset.NewSet()
	for filename, data := range files {
		if !strings.HasSuffix(filename, ".dist-info/METADATA") {
			continue
		}

		wheelInfo := metadata{}

		scanner := bufio.NewScanner(bytes.NewBuffer(data))
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "Name:") {
				wheelInfo.Name = strings.TrimSpace(strings.TrimPrefix(line, "Name:"))
			}
			if strings.HasPrefix(line, "Version:") {
				wheelInfo.Version = strings.TrimSpace(strings.TrimPrefix(line, "Version:"))
			}
		}

		err := versionfmt.Valid(pep440.ParserName, wheelInfo.Version)
		if err != nil {
			log.WithError(err).WithField("version", wheelInfo.Version).Warning("could not parse package version. skipping")
			continue
		}

		if wheelInfo.Name == "" {
			log.WithError(err).WithField("name", wheelInfo.Name).Warning("could not parse package name. skipping")
			continue
		}

		packages.Add(database.Feature{
			Name:          wheelInfo.Name,
			Version:       wheelInfo.Version,
			VersionFormat: pep440.ParserName,
			Type:          database.SourcePackage,
		})
	}

	return database.ConvertFeatureSetToLayerFeatures(packages), nil
}

func (lister) RequiredFilenames() []string {
	return []string{}
}

func init() {
	featurefmt.RegisterLister("python_wheel", "1.0", &lister{})
}
