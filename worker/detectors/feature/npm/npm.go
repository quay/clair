// Copyright 2016 clair authors
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

package npm

import (
	"encoding/json"
	"regexp"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/utils/types"
	"github.com/coreos/clair/worker/detectors"
	"github.com/coreos/pkg/capnslog"
)

var (
	log = capnslog.NewPackageLogger("github.com/coreos/clair", "npm")

	nodejsRegexp = regexp.MustCompile("(node_modules|nodejs)/.*/package.json$")
)

// NpmFeaturesDetector implements FeaturesDetector and detects nodejs packages
type NpmFeaturesDetector struct{}

type NodejsPkg struct {
	Version string `json:"version"`
	Name    string `json:"name"`
}

func init() {
	detectors.RegisterFeaturesDetector("npm", &NpmFeaturesDetector{})
}

// Detect detects packages using *package.json from the input data
func (detector *NpmFeaturesDetector) Detect(data map[string][]byte) ([]database.FeatureVersion, error) {
	// Create a map to store packages and ensure their uniqueness
	packagesMap := make(map[string]database.FeatureVersion)
	for filename, content := range data {
		if !nodejsRegexp.MatchString(filename) {
			continue
		}

		var nodejsPkg NodejsPkg
		err := json.Unmarshal(content, &nodejsPkg)
		if err != nil {
			log.Warningf("could not parse nodejs package file '%s': %s. skipping", filename, err.Error())
			continue
		}

		version, err := types.NewVersion(nodejsPkg.Version)
		if err != nil {
			log.Warningf("could not parse package version '%s': %s. skipping", nodejsPkg.Version, err.Error())
			continue
		}

		pkg := database.FeatureVersion{
			Feature: database.Feature{
				Name: nodejsPkg.Name,
			},
			Version: version,
		}
		packagesMap[pkg.Feature.Name+"#"+pkg.Version.String()] = pkg
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
func (detector *NpmFeaturesDetector) GetRequiredFiles() []*regexp.Regexp {
	return []*regexp.Regexp{nodejsRegexp}
}
