// Copyright 2018 clair authors
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

package database

import (
	"database/sql/driver"
	"errors"
	"fmt"
	"strings"
)

const (
	// NamespaceDetectorType is a type of detector that extracts the namespaces.
	NamespaceDetectorType DetectorType = "namespace"
	// FeatureDetectorType is a type of detector that extracts the features.
	FeatureDetectorType DetectorType = "feature"
)

// DetectorTypes contains all detector types.
var (
	DetectorTypes = []DetectorType{
		NamespaceDetectorType,
		FeatureDetectorType,
	}
	// ErrFailedToParseDetectorType is the error returned when a detector type could
	// not be parsed from a string.
	ErrFailedToParseDetectorType = errors.New("failed to parse DetectorType from input")
	// ErrInvalidDetector is the error returned when a detector from database has
	// invalid name or version or type.
	ErrInvalidDetector = errors.New("the detector has invalid metadata")
)

// DetectorType is the type of a detector.
type DetectorType string

// Value implements the database/sql/driver.Valuer interface.
func (s DetectorType) Value() (driver.Value, error) {
	return string(s), nil
}

// Scan implements the database/sql.Scanner interface.
func (s *DetectorType) Scan(value interface{}) error {
	val, ok := value.([]byte)
	if !ok {
		return errors.New("could not scan a Severity from a non-string input")
	}

	var err error
	*s, err = NewDetectorType(string(val))
	if err != nil {
		return err
	}

	return nil
}

// NewDetectorType attempts to parse a string into a standard DetectorType
// value.
func NewDetectorType(s string) (DetectorType, error) {
	for _, ss := range DetectorTypes {
		if strings.EqualFold(s, string(ss)) {
			return ss, nil
		}
	}

	return "", ErrFailedToParseDetectorType
}

// Valid checks if a detector type is defined.
func (s DetectorType) Valid() bool {
	for _, t := range DetectorTypes {
		if s == t {
			return true
		}
	}

	return false
}

// Detector is an versioned Clair extension.
type Detector struct {
	// Name of an extension should be non-empty and uniquely identifies the
	// extension.
	Name string `json:"name"`
	// Version of an extension should be non-empty.
	Version string `json:"version"`
	// DType is the type of the extension and should be one of the types in
	// DetectorTypes.
	DType DetectorType `json:"dtype"`
}

// Valid checks if all fields in the detector satisfies the spec.
func (d Detector) Valid() bool {
	if d.Name == "" || d.Version == "" || !d.DType.Valid() {
		return false
	}

	return true
}

// String returns a unique string representation of the detector.
func (d Detector) String() string {
	return fmt.Sprintf("%s:%s", d.Name, d.Version)
}

// NewNamespaceDetector returns a new namespace detector.
func NewNamespaceDetector(name, version string) Detector {
	return Detector{
		Name:    name,
		Version: version,
		DType:   NamespaceDetectorType,
	}
}

// NewFeatureDetector returns a new feature detector.
func NewFeatureDetector(name, version string) Detector {
	return Detector{
		Name:    name,
		Version: version,
		DType:   FeatureDetectorType,
	}
}

// SerializeDetectors returns the string representation of given detectors.
func SerializeDetectors(detectors []Detector) []string {
	strDetectors := []string{}
	for _, d := range detectors {
		strDetectors = append(strDetectors, d.String())
	}

	return strDetectors
}
