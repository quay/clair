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

// Package featurens exposes functions to dynamically register methods for
// determining a namespace for features present in an image layer.
package featurens

import (
	"sync"
	"testing"

	"github.com/coreos/pkg/capnslog"
	"github.com/stretchr/testify/assert"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/pkg/tarutil"
)

var (
	log = capnslog.NewPackageLogger("github.com/coreos/clair", "ext/featurens")

	detectorsM sync.RWMutex
	detectors  = make(map[string]Detector)
)

// Detector represents an ability to detect a namespace used for organizing
// features present in an image layer.
type Detector interface {
	// Detect attempts to determine a Namespace from a FilesMap of an image
	// layer.
	Detect(tarutil.FilesMap) (*database.Namespace, error)

	// RequiredFilenames returns the list of files required to be in the FilesMap
	// provided to the Detect method.
	//
	// Filenames must not begin with "/".
	RequiredFilenames() []string
}

// RegisterDetector makes a detector available by the provided name.
//
// If called twice with the same name, the name is blank, or if the provided
// Detector is nil, this function panics.
func RegisterDetector(name string, d Detector) {
	if name == "" {
		panic("namespace: could not register a Detector with an empty name")
	}
	if d == nil {
		panic("namespace: could not register a nil Detector")
	}

	detectorsM.Lock()
	defer detectorsM.Unlock()

	if _, dup := detectors[name]; dup {
		panic("namespace: RegisterDetector called twice for " + name)
	}

	detectors[name] = d
}

// Detect iterators through all registered Detectors and returns the first
// non-nil detected namespace.
func Detect(files tarutil.FilesMap) (*database.Namespace, error) {
	detectorsM.RLock()
	defer detectorsM.RUnlock()

	for name, detector := range detectors {
		namespace, err := detector.Detect(files)
		if err != nil {
			log.Warningf("failed while attempting to detect namespace %s: %s", name, err)
			return nil, err
		}

		if namespace != nil {
			log.Debugf("detected namespace %s: %#v", name, namespace)
			return namespace, nil
		}
	}

	return nil, nil
}

// RequiredFilenames returns the total list of files required for all
// registered Detectors.
func RequiredFilenames() (files []string) {
	detectorsM.RLock()
	defer detectorsM.RUnlock()

	for _, detector := range detectors {
		files = append(files, detector.RequiredFilenames()...)
	}

	return
}

// TestData represents the data used to test an implementation of Detector.
type TestData struct {
	Files             tarutil.FilesMap
	ExpectedNamespace *database.Namespace
}

// TestDetector runs a Detector on each provided instance of TestData and
// asserts the output to be equal to the expected output.
func TestDetector(t *testing.T, d Detector, testData []TestData) {
	for _, td := range testData {
		namespace, err := d.Detect(td.Files)
		assert.Nil(t, err)

		if namespace == nil {
			assert.Equal(t, td.ExpectedNamespace, namespace)
		} else {
			assert.Equal(t, td.ExpectedNamespace.Name, namespace.Name)
		}
	}
}
