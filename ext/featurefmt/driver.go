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

// Package featurefmt exposes functions to dynamically register methods for
// determining the features present in an image layer.
package featurefmt

import (
	"io/ioutil"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/pkg/tarutil"
	"github.com/stretchr/testify/assert"
)

var (
	listersM sync.RWMutex
	listers  = make(map[string]Lister)
)

// Lister represents an ability to list the features present in an image layer.
type Lister interface {
	// ListFeatures produces a list of FeatureVersions present in an image layer.
	ListFeatures(tarutil.FilesMap) ([]database.FeatureVersion, error)

	// RequiredFilenames returns the list of files required to be in the FilesMap
	// provided to the ListFeatures method.
	//
	// Filenames must not begin with "/".
	RequiredFilenames() []string
}

// RegisterLister makes a Lister available by the provided name.
//
// If called twice with the same name, the name is blank, or if the provided
// Lister is nil, this function panics.
func RegisterLister(name string, l Lister) {
	if name == "" {
		panic("featurefmt: could not register a Lister with an empty name")
	}
	if l == nil {
		panic("featurefmt: could not register a nil Lister")
	}

	listersM.Lock()
	defer listersM.Unlock()

	if _, dup := listers[name]; dup {
		panic("featurefmt: RegisterLister called twice for " + name)
	}

	listers[name] = l
}

// ListFeatures produces the list of FeatureVersions in an image layer using
// every registered Lister.
func ListFeatures(files tarutil.FilesMap) ([]database.FeatureVersion, error) {
	listersM.RLock()
	defer listersM.RUnlock()

	var totalFeatures []database.FeatureVersion
	for _, lister := range listers {
		features, err := lister.ListFeatures(files)
		if err != nil {
			return []database.FeatureVersion{}, err
		}
		totalFeatures = append(totalFeatures, features...)
	}

	return totalFeatures, nil
}

// RequiredFilenames returns the total list of files required for all
// registered Listers.
func RequiredFilenames() (files []string) {
	listersM.RLock()
	defer listersM.RUnlock()

	for _, lister := range listers {
		files = append(files, lister.RequiredFilenames()...)
	}

	return
}

// TestData represents the data used to test an implementation of Lister.
type TestData struct {
	Files           tarutil.FilesMap
	FeatureVersions []database.FeatureVersion
}

// LoadFileForTest can be used in order to obtain the []byte contents of a file
// that is meant to be used for test data.
func LoadFileForTest(name string) []byte {
	_, filename, _, _ := runtime.Caller(0)
	d, _ := ioutil.ReadFile(filepath.Join(filepath.Dir(filename)) + "/" + name)
	return d
}

// TestLister runs a Lister on each provided instance of TestData and asserts
// the ouput to be equal to the expected output.
func TestLister(t *testing.T, l Lister, testData []TestData) {
	for _, td := range testData {
		featureVersions, err := l.ListFeatures(td.Files)
		if assert.Nil(t, err) && assert.Len(t, featureVersions, len(td.FeatureVersions)) {
			for _, expectedFeatureVersion := range td.FeatureVersions {
				assert.Contains(t, featureVersions, expectedFeatureVersion)
			}
		}
	}
}
