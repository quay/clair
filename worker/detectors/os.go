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

// Package detectors exposes functions to register and use container
// information extractors.
package detectors

import (
	"fmt"
	"sync"
)

// The OSDetector interface defines a way to detect an Operating System and
// its version from input data
type OSDetector interface {
	// Detect detects an Operating System and its version from input data
	Detect(map[string][]byte) (string, string)
	// GetRequiredFiles returns the list of files required for Detect, without
	// leading /
	GetRequiredFiles() []string
}

var (
	osDetectorsLock sync.Mutex
	osDetectors     = make(map[string]OSDetector)
)

// RegisterOSDetector provides a way to dynamically register an implementation of a
// OSDetector.
//
// If RegisterOSDetector is called twice with the same name if OSDetector is nil,
// or if the name is blank, it panics.
func RegisterOSDetector(name string, f OSDetector) {
	if name == "" {
		panic("Could not register a OSDetector with an empty name")
	}
	if f == nil {
		panic("Could not register a nil OSDetector")
	}

	osDetectorsLock.Lock()
	defer osDetectorsLock.Unlock()

	if _, alreadyExists := osDetectors[name]; alreadyExists {
		panic(fmt.Sprintf("Detector '%s' is already registered", name))
	}
	osDetectors[name] = f
}

// DetectOS finds the OS of the layer by using every registered OSDetector
func DetectOS(data map[string][]byte) string {
	for _, detector := range osDetectors {
		OS, version := detector.Detect(data)
		if OS != "" && version != "" {
			return OS + ":" + version
		}
	}

	return ""
}

// GetRequiredFilesOS returns the list of files required for Detect for every
// registered OSDetector, without leading /
func GetRequiredFilesOS() (files []string) {
	for _, detector := range osDetectors {
		files = append(files, detector.GetRequiredFiles()...)
	}

	return
}
