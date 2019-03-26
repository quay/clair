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

// This package implements a versionfmt.Parser for handling Python PEP-440
// version numbers and range specifiers: https://www.python.org/dev/peps/pep-0440/
package semver

import (
	"errors"
	"github.com/coreos/clair/ext/versionfmt"
	"regexp"
	"strconv"
	"strings"
)

const ParserName = "semver"

const SemVerRegex string = `(?P<major>0|[1-9]\d*)\.(?P<minor>0|[1-9]\d*)\.(?P<patch>0|[1-9]\d*)` +
	`(-(?P<prerelease>[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*))?` +
	`(\+(?P<build>[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*))?` // build metadata gets ignored

const ComparatorRegex string = `(<|>|<=|>=|\^|~)?\s*` + SemVerRegex

var versionRegex *regexp.Regexp
var comparatorRegex *regexp.Regexp

type version struct {
	Major      int
	Minor      int
	Patch      int
	PreRelease []string
}

const (
	LESS    = -1
	EQUAL   = 0
	GREATER = 1
)

const MaxInt = int(^uint(0) >> 1)
const MinInt = -MaxInt - 1

func valid(str string) bool {
	return versionRegex.MatchString(strings.TrimSpace(str))
}

func newVersion(str string) version {
	match := versionRegex.FindStringSubmatch(strings.TrimSpace(str))
	result := make(map[string]string)
	for i, name := range versionRegex.SubexpNames() {
		if i != 0 && name != "" {
			result[name] = match[i]
		}
	}

	var v version
	v.Major, _ = strconv.Atoi(result["major"])
	v.Minor, _ = strconv.Atoi(result["minor"])
	v.Patch, _ = strconv.Atoi(result["patch"])

	if result["prerelease"] != "" {
		v.PreRelease = strings.Split(result["prerelease"], ".")
	}

	return v
}

func compareVersions(a, b version) int {
	if a.Major > b.Major {
		return GREATER
	}
	if a.Major < b.Major {
		return LESS
	}

	if a.Minor > b.Minor {
		return GREATER
	}
	if a.Minor < b.Minor {
		return LESS
	}

	if a.Patch > b.Patch {
		return GREATER
	}
	if a.Patch < b.Patch {
		return LESS
	}

	if len(a.PreRelease) == 0 && len(b.PreRelease) > 0 {
		return GREATER
	}
	if len(a.PreRelease) > 0 && len(b.PreRelease) == 0 {
		return LESS
	}

	if len(a.PreRelease) > len(b.PreRelease) {
		for i, aPart := range a.PreRelease {
			var bPart string
			if i >= len(b.PreRelease) {
				return GREATER
			} else {
				bPart = b.PreRelease[i]
			}

			cmp := compareLocalPart(aPart, bPart)
			if cmp < 0 {
				return LESS
			}

			if cmp > 0 {
				return GREATER
			}
		}
	} else {
		for i, bPart := range b.PreRelease {
			var aPart string
			if i >= len(a.PreRelease) {
				return LESS
			} else {
				aPart = a.PreRelease[i]
			}

			cmp := compareLocalPart(aPart, bPart)
			if cmp < 0 {
				return LESS
			}

			if cmp > 0 {
				return GREATER
			}
		}
	}

	return EQUAL
}

func compareLocalPart(a, b string) int {
	if n1, err := strconv.Atoi(a); err == nil {
		if n2, err := strconv.Atoi(b); err == nil {
			if n1 > n2 {
				return GREATER
			}
			if n2 < n1 {
				return LESS
			}
			return EQUAL
		}
		return LESS
	}

	if _, err := strconv.Atoi(b); err == nil {
		return GREATER
	}

	return strings.Compare(a, b)
}

func evaluateRangePart(v version, rangeDef string) (bool, error) {
	rangeParts := comparatorRegex.FindAllString(rangeDef, -1)
	if rangeParts == nil {
		return false, errors.New("Range spec can not be parsed")
	}

	for _, rangePart := range rangeParts {
		if strings.HasPrefix(rangePart, ">=") {
			rangeSpec := strings.TrimPrefix(rangePart, ">=")
			if !valid(rangeSpec) {
				return false, errors.New("Range spec can not be parsed")
			}

			r := newVersion(rangeSpec)
			if compareVersions(v, r) == LESS {
				return false, nil
			}
		} else if strings.HasPrefix(rangePart, "<=") {
			rangeSpec := strings.TrimPrefix(rangePart, "<=")
			if !valid(rangeSpec) {
				return false, errors.New("Range spec can not be parsed")
			}

			r := newVersion(rangeSpec)
			if compareVersions(v, r) == GREATER {
				return false, nil
			}
		} else if strings.HasPrefix(rangePart, ">") {
			rangeSpec := strings.TrimPrefix(rangePart, ">")
			if !valid(rangeSpec) {
				return false, errors.New("Range spec can not be parsed")
			}

			r := newVersion(rangeSpec)
			if compareVersions(v, r) != GREATER {
				return false, nil
			}
		} else if strings.HasPrefix(rangePart, "<") {
			rangeSpec := strings.TrimPrefix(rangePart, "<")
			if !valid(rangeSpec) {
				return false, errors.New("Range spec can not be parsed")
			}

			r := newVersion(rangeSpec)
			if compareVersions(v, r) != LESS {
				return false, nil
			}
		} else if strings.HasPrefix(rangePart, "~") {
			rangeSpec := strings.TrimPrefix(rangePart, "~")
			if !valid(rangeSpec) {
				return false, errors.New("Range spec can not be parsed")
			}

			r := newVersion(rangeSpec)

			truncatedV := v
			truncatedV.Patch = -1
			truncatedR := r
			truncatedR.Patch = -1
			if compareVersions(v, r) == LESS || compareVersions(truncatedV, truncatedR) != EQUAL {
				return false, nil
			}
		} else if strings.HasPrefix(rangePart, "^") {
			rangeSpec := strings.TrimPrefix(rangePart, "^")
			if !valid(rangeSpec) {
				return false, errors.New("Range spec can not be parsed")
			}

			r := newVersion(rangeSpec)

			truncatedV := v
			truncatedV.Minor = -1
			truncatedV.Patch = -1
			truncatedR := r
			truncatedR.Minor = -1
			truncatedR.Patch = -1
			if compareVersions(v, r) == LESS || compareVersions(truncatedV, truncatedR) != EQUAL {
				return false, nil
			}
		} else {
			if !valid(rangePart) {
				return false, errors.New("Range spec can not be parsed")
			}

			r := newVersion(rangePart)
			if compareVersions(v, r) != EQUAL {
				return false, nil
			}
		}
	}
	return true, nil
}

type parser struct{}

func (p parser) Valid(str string) bool {
	if str == versionfmt.MinVersion {
		return true
	}

	if str == versionfmt.MaxVersion {
		return true
	}

	return valid(str)
}

func (p parser) Compare(a, b string) (int, error) {
	if (a == versionfmt.MinVersion && b == versionfmt.MinVersion) || (a == versionfmt.MaxVersion && b == versionfmt.MaxVersion) {
		return 0, nil
	}

	if a == versionfmt.MinVersion || b == versionfmt.MaxVersion {
		return -1, nil
	}

	if b == versionfmt.MinVersion || a == versionfmt.MaxVersion {
		return 1, nil
	}

	if !valid(a) || !valid(b) {
		return 0, errors.New("Version string can not be parsed")
	}

	v1 := newVersion(a)
	v2 := newVersion(b)

	return compareVersions(v1, v2), nil
}

func (p parser) InRange(str, rangeDef string) (bool, error) {
	rangeDef = strings.TrimSpace(rangeDef)
	if rangeDef == "*" {
		return true, nil
	}

	var v version

	if str == versionfmt.MinVersion {
		v = version{Major: MinInt, Minor: MinInt, Patch: MinInt}
	} else if str == versionfmt.MaxVersion {
		v = version{Major: MaxInt, Minor: MaxInt, Patch: MaxInt}
	} else if !valid(str) {
		return false, errors.New("Version string can not be parsed")
	} else {
		v = newVersion(str)
	}

	for _, orPart := range strings.Split(rangeDef, "||") {
		partResult, err := evaluateRangePart(v, orPart)
		if err != nil {
			return false, err
		}

		if partResult {
			return true, nil
		}
	}

	return false, nil
}

func (p parser) GetFixedIn(fixedIn string) (string, error) {
	// this appears to be unused, and the expected semantics aren't clear
	return fixedIn, nil
}

func init() {
	versionRegex = regexp.MustCompile("^" + SemVerRegex + "$")
	comparatorRegex = regexp.MustCompile(ComparatorRegex)
	versionfmt.RegisterParser(ParserName, parser{})
}
