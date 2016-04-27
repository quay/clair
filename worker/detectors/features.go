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

// The FeaturesDetector interface defines a way to detect packages from input data.
type FeaturesDetector interface {
	// Detect detects a list of FeatureVersion from the input data.
	Detect(map[string][]byte) ([]database.FeatureVersion, error)
	// GetRequiredFiles returns the list of files required for Detect, without
	// leading /.
	GetRequiredFiles() []string
	//Supported checks if the input Namespace is supported by the underling detector
	Supported(namespace database.Namespace) bool
}

var (
	featuresDetectorsLock sync.Mutex
	featuresDetectors     = make(map[string]FeaturesDetector)
)

// RegisterFeaturesDetector makes a FeaturesDetector available for DetectFeatures.
func RegisterFeaturesDetector(name string, f FeaturesDetector) {
	if name == "" {
		panic("Could not register a FeaturesDetector with an empty name")
	}
	if f == nil {
		panic("Could not register a nil FeaturesDetector")
	}

	featuresDetectorsLock.Lock()
	defer featuresDetectorsLock.Unlock()

	if _, alreadyExists := featuresDetectors[name]; alreadyExists {
		panic(fmt.Sprintf("Detector '%s' is already registered", name))
	}
	featuresDetectors[name] = f
}

// DetectFeatures detects a list of FeatureVersion using every registered FeaturesDetector.
func DetectFeatures(data map[string][]byte, namespaces []database.Namespace) ([]database.FeatureVersion, error) {
	var packages []database.FeatureVersion

	for _, detector := range featuresDetectors {
		for _, namespace := range namespaces {
			if detector.Supported(namespace) {
				pkgs, err := detector.Detect(data)
				if err != nil {
					return []database.FeatureVersion{}, err
				}
				// Ensure that every feature has a Namespace associated
				for i := 0; i < len(pkgs); i++ {
					pkgs[i].Feature.Namespace.Name = namespace.Name
					pkgs[i].Feature.Namespace.Version = namespace.Version
				}
				packages = append(packages, pkgs...)
				break
			}
		}
	}

	return packages, nil
}

// GetRequiredFilesFeatures returns the list of files required for Detect for every
// registered FeaturesDetector, without leading /.
func GetRequiredFilesFeatures() (files []string) {
	for _, detector := range featuresDetectors {
		files = append(files, detector.GetRequiredFiles()...)
	}

	return
}
