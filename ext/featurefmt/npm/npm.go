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
package npm

import (
	"encoding/json"
	"github.com/coreos/clair/database"
	"github.com/coreos/clair/ext/featurefmt"
	"github.com/coreos/clair/ext/versionfmt"
	"github.com/coreos/clair/ext/versionfmt/semver"
	"github.com/coreos/clair/pkg/tarutil"
	"github.com/deckarep/golang-set"
	log "github.com/sirupsen/logrus"
	"strings"
)

type npmPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type lister struct{}

var ns database.Namespace

func (lister) ListFeatures(files tarutil.FilesMap) ([]database.LayerFeature, error) {
	packages := mapset.NewSet()
	for filename, data := range files {
		if !strings.HasSuffix(filename, "/package.json") {
			continue
		}

		packageJson := npmPackage{}
		if err := json.Unmarshal(data, &packageJson); err != nil {
			log.WithError(err).WithField("filename", filename).Warning("unable to parse package.json, skipping")
			continue
		}

		err := versionfmt.Valid(semver.ParserName, packageJson.Version)
		if err != nil {
			log.WithError(err).WithField("version", packageJson.Version).Warning("could not parse package version. skipping")
			continue
		}

		packages.Add(database.Feature{
			Name:          packageJson.Name,
			Version:       packageJson.Version,
			VersionFormat: semver.ParserName,
			Type:          database.SourcePackage,
		})
	}

	layerFeatures := database.ConvertFeatureSetToLayerFeatures(packages)
	for _, layerFeature := range layerFeatures {
		layerFeature.PotentialNamespace = ns
	}
	return layerFeatures, nil
}

func (lister) RequiredFilenames() []string {
	return []string{`package\.json`}
}

func init() {
	ns = *database.NewNamespace("npm", semver.ParserName)
	featurefmt.RegisterLister("npm", "1.0", &lister{})
}
