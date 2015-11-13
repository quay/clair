// Copyright 2015 clair authors
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

package detectors

import (
	"fmt"
	"sync"

	"github.com/coreos/clair/database"
)

// The PackagesDetector interface defines a way to detect packages from input data
type PackagesDetector interface {
	// Detect detects packages from the input data
	Detect(map[string][]byte) ([]*database.Package, error)
	// GetRequiredFiles returns the list of files required for Detect, without
	// leading /
	GetRequiredFiles() []string
}

var (
	packagesDetectorsLock sync.Mutex
	packagesDetectors     = make(map[string]PackagesDetector)
)

// RegisterPackagesDetector makes a PackagesDetector available for DetectPackages
func RegisterPackagesDetector(name string, f PackagesDetector) {
	if name == "" {
		panic("Could not register a PackagesDetector with an empty name")
	}
	if f == nil {
		panic("Could not register a nil PackagesDetector")
	}

	packagesDetectorsLock.Lock()
	defer packagesDetectorsLock.Unlock()

	if _, alreadyExists := packagesDetectors[name]; alreadyExists {
		panic(fmt.Sprintf("Detector '%s' is already registered", name))
	}
	packagesDetectors[name] = f
}

// DetectPackages detects packages using every registered PackagesDetector
func DetectPackages(data map[string][]byte) ([]*database.Package, error) {
	var packages []*database.Package

	for _, detector := range packagesDetectors {
		pkgs, err := detector.Detect(data)
		if err != nil {
			return []*database.Package{}, err
		}
		packages = append(packages, pkgs...)
	}

	return packages, nil
}

// GetRequiredFilesPackages returns the list of files required for Detect for every
// registered PackagesDetector, without leading /
func GetRequiredFilesPackages() (files []string) {
	for _, detector := range packagesDetectors {
		files = append(files, detector.GetRequiredFiles()...)
	}

	return
}
