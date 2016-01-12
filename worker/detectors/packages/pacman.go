// Copyright 2015, 2016 clair authors
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

// Package packages defines PackagesDetector for several sources.
package packages

import (
	"bufio"
	"strings"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/utils"
	"github.com/coreos/clair/utils/types"
	"github.com/coreos/clair/worker/detectors"
)

// PacmanPackagesDetector implements PackagesDetector and detects pacman packages
type PacmanPackagesDetector struct{}

func init() {
	detectors.RegisterPackagesDetector("pacman", &PacmanPackagesDetector{})
}

// Detect detects packages using /var/lib/pacman/local from the input data
func (detector *PacmanPackagesDetector) Detect(data map[string][]byte) ([]*database.Package, error) {
	log.Errorf("Pacman: %v", data)
	db, hasFile := data["var/lib/pacman"]
	if !hasFile {
		return []*database.Package{}, nil
	}

	// Create a map to store packages and ensure their uniqueness
	packagesMap := make(map[string]*database.Package)

	// Query Pacman to retrieve all of native packages with their version
	out, err := utils.Exec("", "pacman", "-Qn", "-b", string(db))
	if err != nil {
		log.Errorf("could not query Pacman: %s. output: %s", err, string(out))
		return []*database.Package{}, nil
	}

	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := strings.Split(scanner.Text(), " ")
		version, err := types.NewVersion(line[1])
		if err != nil {
			log.Warningf(
				"could not parse package version '%s': %s. skipping",
				line[1], err.Error())
			continue
		}
		// Add package
		pkg := &database.Package{
			Name:    line[0],
			Version: version,
		}
		packagesMap[pkg.Key()] = pkg
	}
	return mapToSlice(packagesMap), nil
}

// GetRequiredFiles returns the list of files required for Detect, without
// leading /
func (detector *PacmanPackagesDetector) GetRequiredFiles() []string {
	return []string{"var/lib/pacman"}
}
