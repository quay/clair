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

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/pkg/tarutil"
)

var (
	detectorsM sync.RWMutex
	detectors  = make(map[string]detector)
)

// Detector represents an ability to detect a namespace used for organizing
// features present in an image layer.
type Detector interface {
	// Detect attempts to determine a Namespace from a FilesMap of an image
	// layer.
	Detect(tarutil.FilesMap) (*database.Namespace, error)

	// RequiredFilenames returns a list of patterns for filenames that will
	// be in the FilesMap provided to the Detect method.
	//
	// The patterns are expressed as regexps, and will be matched against
	// full paths that do not include the leading "/".
	RequiredFilenames() []string
}

type detector struct {
	Detector

	info database.Detector
}

// RegisterDetector makes a detector available by the provided name.
//
// If called twice with the same name, the name is blank, or if the provided
// Detector is nil, this function panics.
func RegisterDetector(name string, version string, d Detector) {
	if name == "" || version == "" {
		panic("namespace: could not register a Detector with an empty name or version")
	}
	if d == nil {
		panic("namespace: could not register a nil Detector")
	}

	detectorsM.Lock()
	defer detectorsM.Unlock()

	if _, ok := detectors[name]; ok {
		panic("namespace: RegisterDetector called twice for " + name)
	}

	detectors[name] = detector{d, database.NewNamespaceDetector(name, version)}
}

// Detect uses detectors specified to retrieve the detect result.
func Detect(files tarutil.FilesMap, toUse []database.Detector) ([]database.LayerNamespace, error) {
	detectorsM.RLock()
	defer detectorsM.RUnlock()

	namespaces := []database.LayerNamespace{}
	for _, d := range toUse {
		// Only use the detector with the same type
		if d.DType != database.NamespaceDetectorType {
			continue
		}

		if detector, ok := detectors[d.Name]; ok {
			namespace, err := detector.Detect(files)
			if err != nil {
				log.WithError(err).WithField("detector", d).Warning("failed while attempting to detect namespace")
				return nil, err
			}

			if namespace != nil {
				log.WithFields(log.Fields{"detector": d, "namespace": namespace.Name}).Debug("detected namespace")
				namespaces = append(namespaces, database.LayerNamespace{
					Namespace: *namespace,
					By:        detector.info,
				})
			}
		} else {
			log.WithField("detector", d).Fatal("unknown namespace detector")
		}
	}

	return namespaces, nil
}

// RequiredFilenames returns all file patterns that will be passed to the
// given extensions. These patterns are expressed as regexps. Any extension
// metadata that has non namespace-detector type will be skipped.
func RequiredFilenames(toUse []database.Detector) (files []string) {
	detectorsM.RLock()
	defer detectorsM.RUnlock()

	for _, d := range toUse {
		if d.DType != database.NamespaceDetectorType {
			continue
		}

		files = append(files, detectors[d.Name].RequiredFilenames()...)
	}

	return
}

// ListDetectors returns the info of all registered namespace detectors.
func ListDetectors() []database.Detector {
	r := make([]database.Detector, 0, len(detectors))
	for _, d := range detectors {
		r = append(r, d.info)
	}
	return r
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
