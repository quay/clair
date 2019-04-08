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
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/pkg/tarutil"
)

var (
	listersM sync.RWMutex
	listers  = make(map[string]lister)
)

// Lister represents an ability to list the features present in an image layer.
type Lister interface {
	// ListFeatures produces a list of Features present in an image layer.
	ListFeatures(tarutil.FilesMap) ([]database.LayerFeature, error)

	// RequiredFilenames returns a list of patterns for filenames that will
	// be in the FilesMap provided to the ListFeatures method.
	//
	// The patterns are expressed as regexps, and will be matched against
	// full paths that do not include the leading "/".
	RequiredFilenames() []string
}

type lister struct {
	Lister

	info database.Detector
}

// RegisterLister makes a Lister available by the provided name.
//
// If called twice with the same name, the name is blank, or if the provided
// Lister is nil, this function panics.
func RegisterLister(name string, version string, l Lister) {
	if name == "" || version == "" {
		panic("featurefmt: could not register a Lister with an empty name or version")
	}
	if l == nil {
		panic("featurefmt: could not register a nil Lister")
	}

	listersM.Lock()
	defer listersM.Unlock()

	if _, dup := listers[name]; dup {
		panic("featurefmt: RegisterLister called twice for " + name)
	}

	listers[name] = lister{l, database.NewFeatureDetector(name, version)}
}

// ListFeatures produces the list of Features in an image layer using
// every registered Lister.
func ListFeatures(files tarutil.FilesMap, toUse []database.Detector) ([]database.LayerFeature, error) {
	listersM.RLock()
	defer listersM.RUnlock()

	features := []database.LayerFeature{}
	for _, d := range toUse {
		// Only use the detector with the same type
		if d.DType != database.FeatureDetectorType {
			continue
		}

		if lister, ok := listers[d.Name]; ok {
			fs, err := lister.ListFeatures(files)
			if err != nil {
				return nil, err
			}

			for i := range fs {
				fs[i].By = lister.info
			}
			features = append(features, fs...)

		} else {
			log.WithField("Name", d).Fatal("unknown feature detector")
		}
	}

	return features, nil
}

// RequiredFilenames returns all file patterns that will be passed to the
// given extensions. These patterns are expressed as regexps. Any extension
// metadata that has non feature-detector type will be skipped.
func RequiredFilenames(toUse []database.Detector) (files []string) {
	listersM.RLock()
	defer listersM.RUnlock()

	for _, d := range toUse {
		if d.DType != database.FeatureDetectorType {
			continue
		}

		files = append(files, listers[d.Name].RequiredFilenames()...)
	}

	return
}

// ListListers returns the names of all the registered feature listers.
func ListListers() []database.Detector {
	r := []database.Detector{}
	for _, d := range listers {
		r = append(r, d.info)
	}
	return r
}
