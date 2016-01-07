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
	"io"
	"net/http"
	"os"
	"strings"
	"sync"

	cerrors "github.com/coreos/clair/utils/errors"
)

// The DataDetector interface defines a way to detect the required data from input path
type DataDetector interface {
	//Support check if the input path and format are supported by the underling detector
	Supported(path string, format string) bool
	// Detect detects the required data from input path
	Detect(layerReader io.ReadCloser, toExtract []string, maxFileSize int64) (data map[string][]byte, err error)
}

var (
	dataDetectorsLock sync.Mutex
	dataDetectors     = make(map[string]DataDetector)
)

// RegisterDataDetector provides a way to dynamically register an implementation of a
// DataDetector.
//
// If RegisterDataDetector is called twice with the same name if DataDetector is nil,
// or if the name is blank, it panics.
func RegisterDataDetector(name string, f DataDetector) {
	if name == "" {
		panic("Could not register a DataDetector with an empty name")
	}
	if f == nil {
		panic("Could not register a nil DataDetector")
	}

	dataDetectorsLock.Lock()
	defer dataDetectorsLock.Unlock()

	if _, alreadyExists := dataDetectors[name]; alreadyExists {
		panic(fmt.Sprintf("Detector '%s' is already registered", name))
	}
	dataDetectors[name] = f
}

// DetectData finds the Data of the layer by using every registered DataDetector
func DetectData(path string, format string, toExtract []string, maxFileSize int64) (data map[string][]byte, err error) {
	var layerReader io.ReadCloser
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		r, err := http.Get(path)
		if err != nil {
			return nil, cerrors.ErrCouldNotDownload
		}
		layerReader = r.Body
	} else {
		layerReader, err = os.Open(path)
		if err != nil {
			return nil, cerrors.ErrNotFound
		}
	}
	defer layerReader.Close()

	for _, detector := range dataDetectors {
		if detector.Supported(path, format) {
			if data, err = detector.Detect(layerReader, toExtract, maxFileSize); err == nil {
				return data, nil
			}
		}
	}

	return nil, nil
}
