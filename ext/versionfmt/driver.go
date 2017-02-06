// Copyright 2016 clair authors
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

// Package versionfmt exposes functions to dynamically register formats used to
// parse Feature Versions.
package versionfmt

import (
	"errors"
	"sync"

	"github.com/coreos/pkg/capnslog"
)

const (
	// MinVersion is a special package version which is always sorted first.
	MinVersion = "#MINV#"

	// MaxVersion is a special package version which is always sorted last.
	MaxVersion = "#MAXV#"
)

var (
	// ErrUnknownVersionFormat is returned when a function does not have enough
	// context to determine the format of a version.
	ErrUnknownVersionFormat = errors.New("unknown version format")

	// ErrInvalidVersion is returned when a function needs to validate a version,
	// but should return an error in the case where the version is invalid.
	ErrInvalidVersion = errors.New("invalid version")

	nlog = capnslog.NewPackageLogger("github.com/coreos/clair", "ext/versionfmt")

	parsersM sync.Mutex
	parsers  = make(map[string]Parser)
)

// Parser represents any format that can compare two version strings.
type Parser interface {
	// Valid attempts to parse a version string and returns its success.
	Valid(string) bool

	// Compare parses two different version strings.
	// Returns 0 when equal, -1 when a < b, 1 when b < a.
	Compare(a, b string) (int, error)
}

// RegisterParser provides a way to dynamically register an implementation of a
// Parser.
//
// If RegisterParser is called twice with the same name, the name is blank, or
// if the provided Parser is nil, this function panics.
func RegisterParser(name string, p Parser) {
	if name == "" {
		panic("versionfmt: could not register a Parser with an empty name")
	}

	if p == nil {
		panic("versionfmt: could not register a nil Parser")
	}

	parsersM.Lock()
	defer parsersM.Unlock()

	if _, dup := parsers[name]; dup {
		panic("versionfmt: RegisterParser called twice for " + name)
	}

	parsers[name] = p
}

// GetParser returns the registered Parser with a provided name.
func GetParser(name string) (p Parser, exists bool) {
	parsersM.Lock()
	defer parsersM.Unlock()

	p, exists = parsers[name]
	return
}

// Valid is a helper function that will return an error if the version fails to
// validate with a given format.
func Valid(format, version string) error {
	versionParser, exists := GetParser(format)
	if !exists {
		return ErrUnknownVersionFormat
	}

	if !versionParser.Valid(version) {
		return ErrInvalidVersion
	}

	return nil
}

// Compare is a helper function that will compare two versions with a given
// format and return an error if there are any failures.
func Compare(format, versionA, versionB string) (int, error) {
	versionParser, exists := GetParser(format)
	if !exists {
		return 0, ErrUnknownVersionFormat
	}

	return versionParser.Compare(versionA, versionB)
}
