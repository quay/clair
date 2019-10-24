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

// Package imgpostprocessor process image after Clair detected features
// and namespace. This module supports plugins and can be used for sharing
// information between layers.

// Package imgpostprocessor exposes functions to dynamically register methods
// which can do different types of post-processing methods.
package imgpostprocessor

import (
	"strings"
	"sync"

	"github.com/quay/clair/v3/database"
)

var (
	postProcessorMutex sync.RWMutex
	postProcessors     = make(map[string]PostProcessor)
)

// PostProcessor represents an ability to post-process content in a particular
// container image.
type PostProcessor interface {
	// ExtractFiles produces a tarutil.FilesMap from a image layer.
	PostProcessImage(layers []*database.LayerScanResult) ([]*database.LayerScanResult, error)
}

// RegisterPostProcessor makes an post-processor available by the provided name.
// If called twice with the same name, the name is blank, or if the provided
// Extractor is nil, this function panics.
func RegisterPostProcessor(name string, postProcessor PostProcessor) {
	postProcessorMutex.Lock()
	defer postProcessorMutex.Unlock()

	if name == "" {
		panic("PostProcessor: could not register an PostProcessor with an empty name")
	}

	if postProcessor == nil {
		panic("PostProcessor: could not register a nil PostProcessor")
	}

	// Enforce lowercase names, so that they can be reliably be found in a map.
	name = strings.ToLower(name)

	if _, dup := postProcessors[name]; dup {
		panic("PostProcessor: RegisterPostProcessor called twice for " + name)
	}

	postProcessors[name] = postProcessor
}

// PostProcessors returns the list of the registered post-processors.
func PostProcessors() map[string]PostProcessor {
	postProcessorMutex.RLock()
	defer postProcessorMutex.RUnlock()

	ret := make(map[string]PostProcessor)
	for k, v := range postProcessors {
		ret[k] = v
	}

	return ret
}

// UnregisterExtractor removes a PostProcessor with a particular name from the list.
func UnregisterExtractor(name string) {
	postProcessorMutex.Lock()
	defer postProcessorMutex.Unlock()
	delete(postProcessors, name)
}

// PostProcessImage post-process image will all registered post-processors.
func PostProcessImage(layers []*database.LayerScanResult) ([]*database.LayerScanResult, error) {
	var err error
	for _, postProcessor := range PostProcessors() {
		layers, err = postProcessor.PostProcessImage(layers)
		if err != nil {
			return nil, err
		}
	}
	return layers, nil
}
