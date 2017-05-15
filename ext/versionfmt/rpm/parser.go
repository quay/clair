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

// Package rpm implements a versionfmt.Parser for version numbers used in rpm
// based software packages.
package rpm

import (
	"errors"
	"math"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"github.com/coreos/clair/ext/versionfmt"
)

// ParserName is the name by which the rpm parser is registered.
const ParserName = "rpm"

var (
	// alphanumPattern is a regular expression to match all sequences of numeric
	// characters or alphanumeric characters.
	alphanumPattern = regexp.MustCompile("([a-zA-Z]+)|([0-9]+)|(~)")
	allowedSymbols  = []rune{'.', '-', '+', '~', ':', '_'}
)

type version struct {
	epoch   int
	version string
	release string
}

var (
	minVersion = version{version: versionfmt.MinVersion}
	maxVersion = version{version: versionfmt.MaxVersion}
)

// newVersion parses a string into a version type which can be compared.
func newVersion(str string) (version, error) {
	var v version

	// Trim leading and trailing space
	str = strings.TrimSpace(str)

	if len(str) == 0 {
		return version{}, errors.New("Version string is empty")
	}

	// Max/Min versions
	if str == maxVersion.String() {
		return maxVersion, nil
	}
	if str == minVersion.String() {
		return minVersion, nil
	}

	// Find epoch
	sepepoch := strings.Index(str, ":")
	if sepepoch > -1 {
		intepoch, err := strconv.Atoi(str[:sepepoch])
		if err == nil {
			v.epoch = intepoch
		} else {
			return version{}, errors.New("epoch in version is not a number")
		}
		if intepoch < 0 {
			return version{}, errors.New("epoch in version is negative")
		}
	} else {
		v.epoch = 0
	}

	// Find version / release
	seprevision := strings.Index(str, "-")
	if seprevision > -1 {
		v.version = str[sepepoch+1 : seprevision]
		v.release = str[seprevision+1:]
	} else {
		v.version = str[sepepoch+1:]
		v.release = ""
	}
	// Verify format
	if len(v.version) == 0 {
		return version{}, errors.New("No version")
	}

	for i := 0; i < len(v.version); i = i + 1 {
		r := rune(v.version[i])
		if !unicode.IsDigit(r) && !unicode.IsLetter(r) && !validSymbol(r) {
			return version{}, errors.New("invalid character in version")
		}
	}

	for i := 0; i < len(v.release); i = i + 1 {
		r := rune(v.release[i])
		if !unicode.IsDigit(r) && !unicode.IsLetter(r) && !validSymbol(r) {
			return version{}, errors.New("invalid character in revision")
		}
	}

	return v, nil
}

type parser struct{}

func (p parser) Valid(str string) bool {
	_, err := newVersion(str)
	return err == nil
}

func (p parser) Compare(a, b string) (int, error) {
	v1, err := newVersion(a)
	if err != nil {
		return 0, err
	}

	v2, err := newVersion(b)
	if err != nil {
		return 0, err
	}

	// Quick check
	if v1 == v2 {
		return 0, nil
	}

	// Max/Min comparison
	if v1 == minVersion || v2 == maxVersion {
		return -1, nil
	}
	if v2 == minVersion || v1 == maxVersion {
		return 1, nil
	}

	// Compare epochs
	if v1.epoch > v2.epoch {
		return 1, nil
	}
	if v1.epoch < v2.epoch {
		return -1, nil
	}

	// Compare version
	rc := rpmvercmp(v1.version, v2.version)
	if rc != 0 {
		return rc, nil
	}

	// Compare revision
	return rpmvercmp(v1.release, v2.release), nil
}

// rpmcmpver compares two version or release strings.
//
// Lifted from github.com/cavaliercoder/go-rpm.
// For the original C implementation, see:
// https://github.com/rpm-software-management/rpm/blob/master/lib/rpmvercmp.c#L16
func rpmvercmp(strA, strB string) int {
	// shortcut for equality
	if strA == strB {
		return 0
	}

	// get alpha/numeric segements
	segsa := alphanumPattern.FindAllString(strA, -1)
	segsb := alphanumPattern.FindAllString(strB, -1)
	segs := int(math.Min(float64(len(segsa)), float64(len(segsb))))

	// compare each segment
	for i := 0; i < segs; i++ {
		a := segsa[i]
		b := segsb[i]

		// compare tildes
		if []rune(a)[0] == '~' && []rune(b)[0] == '~' {
			continue
		}
		if []rune(a)[0] == '~' && []rune(b)[0] != '~' {
			return -1
		}
		if []rune(a)[0] != '~' && []rune(b)[0] == '~' {
			return 1
		}

		if unicode.IsNumber([]rune(a)[0]) {
			// numbers are always greater than alphas
			if !unicode.IsNumber([]rune(b)[0]) {
				// a is numeric, b is alpha
				return 1
			}

			// trim leading zeros
			a = strings.TrimLeft(a, "0")
			b = strings.TrimLeft(b, "0")

			// longest string wins without further comparison
			if len(a) > len(b) {
				return 1
			} else if len(b) > len(a) {
				return -1
			}
		} else if unicode.IsNumber([]rune(b)[0]) {
			// a is alpha, b is numeric
			return -1
		}

		// string compare
		if a < b {
			return -1
		} else if a > b {
			return 1
		}
	}

	// segments were all the same but separators must have been different
	if len(segsa) == len(segsb) {
		return 0
	}

	// If there is a tilde in a segment past the min number of segments, find it.
	if len(segsa) > segs && []rune(segsa[segs])[0] == '~' {
		return -1
	} else if len(segsb) > segs && []rune(segsb[segs])[0] == '~' {
		return 1
	}

	// whoever has the most segments wins
	if len(segsa) > len(segsb) {
		return 1
	}

	return -1
}

// String returns the string representation of a Version.
func (v version) String() (s string) {
	if v.epoch != 0 {
		s = strconv.Itoa(v.epoch) + ":"
	}
	s += v.version
	if v.release != "" {
		s += "-" + v.release
	}
	return
}

func validSymbol(r rune) bool {
	return containsRune(allowedSymbols, r)
}

func containsRune(s []rune, e rune) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func init() {
	versionfmt.RegisterParser(ParserName, parser{})
}
