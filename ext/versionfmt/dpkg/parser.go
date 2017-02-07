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

// Package dpkg implements a versionfmt.Parser for version numbers used in dpkg
// based software packages.
package dpkg

import (
	"errors"
	"strconv"
	"strings"
	"unicode"

	"github.com/coreos/clair/ext/versionfmt"
)

// ParserName is the name by which the dpkg parser is registered.
const ParserName = "dpkg"

type version struct {
	epoch    int
	version  string
	revision string
}

var (
	minVersion = version{version: versionfmt.MinVersion}
	maxVersion = version{version: versionfmt.MaxVersion}

	versionAllowedSymbols  = []rune{'.', '-', '+', '~', ':', '_'}
	revisionAllowedSymbols = []rune{'.', '+', '~', '_'}
)

// newVersion function parses a string into a Version struct which can be compared
//
// The implementation is based on http://man.he.net/man5/deb-version
// on https://www.debian.org/doc/debian-policy/ch-controlfields.html#s-f-Version
//
// It uses the dpkg-1.17.25's algorithm  (lib/parsehelp.c)
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

	// Find version / revision
	seprevision := strings.LastIndex(str, "-")
	if seprevision > -1 {
		v.version = str[sepepoch+1 : seprevision]
		v.revision = str[seprevision+1:]
	} else {
		v.version = str[sepepoch+1:]
		v.revision = ""
	}
	// Verify format
	if len(v.version) == 0 {
		return version{}, errors.New("No version")
	}

	for i := 0; i < len(v.version); i = i + 1 {
		r := rune(v.version[i])
		if !unicode.IsDigit(r) && !unicode.IsLetter(r) && !containsRune(versionAllowedSymbols, r) {
			return version{}, errors.New("invalid character in version")
		}
	}

	for i := 0; i < len(v.revision); i = i + 1 {
		r := rune(v.revision[i])
		if !unicode.IsDigit(r) && !unicode.IsLetter(r) && !containsRune(revisionAllowedSymbols, r) {
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

// Compare function compares two Debian-like package version
//
// The implementation is based on http://man.he.net/man5/deb-version
// on https://www.debian.org/doc/debian-policy/ch-controlfields.html#s-f-Version
//
// It uses the dpkg-1.17.25's algorithm  (lib/version.c)
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
	rc := verrevcmp(v1.version, v2.version)
	if rc != 0 {
		return signum(rc), nil
	}

	// Compare revision
	return signum(verrevcmp(v1.revision, v2.revision)), nil
}

// String returns the string representation of a Version.
func (v version) String() (s string) {
	if v.epoch != 0 {
		s = strconv.Itoa(v.epoch) + ":"
	}
	s += v.version
	if v.revision != "" {
		s += "-" + v.revision
	}
	return
}

func verrevcmp(t1, t2 string) int {
	t1, rt1 := nextRune(t1)
	t2, rt2 := nextRune(t2)

	for rt1 != nil || rt2 != nil {
		firstDiff := 0

		for (rt1 != nil && !unicode.IsDigit(*rt1)) || (rt2 != nil && !unicode.IsDigit(*rt2)) {
			ac := 0
			bc := 0
			if rt1 != nil {
				ac = order(*rt1)
			}
			if rt2 != nil {
				bc = order(*rt2)
			}

			if ac != bc {
				return ac - bc
			}

			t1, rt1 = nextRune(t1)
			t2, rt2 = nextRune(t2)
		}
		for rt1 != nil && *rt1 == '0' {
			t1, rt1 = nextRune(t1)
		}
		for rt2 != nil && *rt2 == '0' {
			t2, rt2 = nextRune(t2)
		}
		for rt1 != nil && unicode.IsDigit(*rt1) && rt2 != nil && unicode.IsDigit(*rt2) {
			if firstDiff == 0 {
				firstDiff = int(*rt1) - int(*rt2)
			}
			t1, rt1 = nextRune(t1)
			t2, rt2 = nextRune(t2)
		}
		if rt1 != nil && unicode.IsDigit(*rt1) {
			return 1
		}
		if rt2 != nil && unicode.IsDigit(*rt2) {
			return -1
		}
		if firstDiff != 0 {
			return firstDiff
		}
	}

	return 0
}

// order compares runes using a modified ASCII table
// so that letters are sorted earlier than non-letters
// and so that tildes sorts before anything
func order(r rune) int {
	if unicode.IsDigit(r) {
		return 0
	}

	if unicode.IsLetter(r) {
		return int(r)
	}

	if r == '~' {
		return -1
	}

	return int(r) + 256
}

func nextRune(str string) (string, *rune) {
	if len(str) >= 1 {
		r := rune(str[0])
		return str[1:], &r
	}
	return str, nil
}

func containsRune(s []rune, e rune) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func signum(a int) int {
	switch {
	case a < 0:
		return -1
	case a > 0:
		return +1
	}

	return 0
}

func init() {
	versionfmt.RegisterParser(ParserName, parser{})
}
