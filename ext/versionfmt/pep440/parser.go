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
package pep440

import (
	"errors"
	"github.com/coreos/clair/ext/versionfmt"
	"regexp"
	"strconv"
	"strings"
)

const ParserName = "pep440"

const PEP440Regex string = `^v?` +
	`((?P<epoch>[1-9]\d*)!)?` +
	`(?P<release>(0|[1-9]\d*)(\.(0|[1-9]\d*))*)` +
	`([\-_\.]?(?P<pretype>a|alpha|b|beta|rc|c|pre|preview)[\-_\.]?(?P<prerelease>0|[1-9]\d*)?)?` +
	`(?P<post>-(?P<postrelease1>[0-9]+)|([\-_\.]?post[\-_\.]?(?P<postrelease2>0|[1-9]\d*)?))?` +
	`(?P<dev>[\-_\.]?dev(?P<devrelease>0|[1-9]\d*)?)?` +
	`(\+(?P<local>[a-z0-9]+([\-_\.][a-z0-9]+)*))?$` // from appendix B of PEP-440

var versionRegex *regexp.Regexp

var seperatorNormaliser = strings.NewReplacer("-", ".", "_", ".")

type version struct {
	Epoch       int
	Release     []int
	PreType     int
	PreRelease  int
	PostRelease int
	DevRelease  int
	Local       []string
}

const (
	ALPHA = 1
	BETA  = 2
	RC    = 3
	FINAL = 4

	LESS    = -1
	EQUAL   = 0
	GREATER = 1

	STAR_MATCH = -2
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
	v.Epoch, _ = strconv.Atoi(result["epoch"])

	releaseParts := strings.Split(result["release"], ".")
	v.Release = make([]int, len(releaseParts))
	for i, releasePart := range releaseParts {
		v.Release[i], _ = strconv.Atoi(releasePart)
	}

	switch strings.ToLower(result["pretype"]) {
	case "a", "alpha":
		v.PreType = ALPHA
	case "b", "beta":
		v.PreType = BETA
	case "rc", "c", "pre", "preview":
		v.PreType = RC
	default:
		v.PreType = FINAL
	}

	if v.PreType < FINAL {
		v.PreRelease, _ = strconv.Atoi(result["prerelease"])
	} else {
		v.PreRelease = -1
	}

	if result["post"] != "" {
		if n, err := strconv.Atoi(result["postrelease1"]); err == nil {
			v.PostRelease = n
		} else {
			v.PostRelease, _ = strconv.Atoi(result["postrelease2"])
		}
	} else {
		v.PostRelease = -1
	}

	if result["dev"] != "" {
		v.DevRelease, _ = strconv.Atoi(result["devrelease"])
	} else {
		v.DevRelease = -1
	}

	if result["local"] != "" {
		v.Local = strings.Split(seperatorNormaliser.Replace(result["local"]), ".")
	}

	return v
}

func compareVersions(a, b version) int {
	if a.Epoch > b.Epoch {
		return GREATER
	}
	if a.Epoch < b.Epoch {
		return LESS
	}

	if len(a.Release) > len(b.Release) {
		for i, aPart := range a.Release {
			var bPart int
			if i >= len(b.Release) {
				bPart = 0
			} else {
				bPart = b.Release[i]
			}

			if aPart == STAR_MATCH || bPart == STAR_MATCH {
				return EQUAL
			}

			if aPart > bPart {
				return GREATER
			}

			if aPart < bPart {
				return LESS
			}
		}
	} else {
		for i, bPart := range b.Release {
			var aPart int
			if i >= len(a.Release) {
				aPart = 0
			} else {
				aPart = a.Release[i]
			}

			if aPart == STAR_MATCH || bPart == STAR_MATCH {
				return EQUAL
			}

			if aPart > bPart {
				return GREATER
			}

			if aPart < bPart {
				return LESS
			}
		}
	}

	if a.DevRelease == -1 && b.DevRelease > -1 {
		return GREATER
	}
	if b.DevRelease == -1 && a.DevRelease > -1 {
		return LESS
	}

	if a.PreType > b.PreType {
		return GREATER
	}
	if a.PreType < b.PreType {
		return LESS
	}

	if a.PreRelease > b.PreRelease {
		return GREATER
	}
	if a.PreRelease < b.PreRelease {
		return LESS
	}

	if a.PostRelease > b.PostRelease {
		return GREATER
	}
	if a.PostRelease < b.PostRelease {
		return LESS
	}

	if a.DevRelease > b.DevRelease {
		return GREATER
	}
	if a.DevRelease < b.DevRelease {
		return LESS
	}

	if len(a.Local) > len(b.Local) {
		for i, aPart := range a.Local {
			var bPart string
			if i >= len(b.Local) {
				return GREATER
			} else {
				bPart = b.Local[i]
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
		for i, bPart := range b.Local {
			var aPart string
			if i >= len(a.Local) {
				return LESS
			} else {
				aPart = a.Local[i]
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
		return GREATER
	}

	if _, err := strconv.Atoi(b); err == nil {
		return LESS
	}

	return strings.Compare(a, b)
}

func evaluateRangePart(v version, rangeDef string) (bool, error) {
	rangeDef = strings.TrimSpace(rangeDef)

	if strings.HasPrefix(rangeDef, "~=") {
		rangeSpec := strings.TrimPrefix(rangeDef, "~=")
		if !valid(rangeSpec) {
			return false, errors.New("Range spec can not be parsed")
		}

		r := newVersion(rangeSpec)
		if len(r.Local) > 0 {
			return false, errors.New("Range spec specified local part, which is not permitted")
		}

		r2 := r
		r2.Release = make([]int, len(r.Release))
		copy(r2.Release, r.Release)
		r2.Release[len(r2.Release)-1] = STAR_MATCH

		return compareVersions(v, r) > LESS && compareVersions(v, r2) == EQUAL, nil
	} else if strings.HasPrefix(rangeDef, "==") {
		rangeSpec := strings.TrimPrefix(rangeDef, "==")
		isGlob := false

		if strings.HasSuffix(rangeSpec, ".*") {
			isGlob = true
			rangeSpec = strings.TrimSuffix(rangeSpec, ".*")
		}
		if !valid(rangeSpec) {
			return false, errors.New("Range spec can not be parsed")
		}

		r := newVersion(rangeSpec)
		if len(r.Local) > 0 {
			return false, errors.New("Range spec specified local part, which is not permitted")
		}

		if isGlob {
			r.Release = append(r.Release, STAR_MATCH)
		}

		return compareVersions(v, r) == EQUAL, nil
	} else if strings.HasPrefix(rangeDef, "!=") {
		rangeSpec := strings.TrimPrefix(rangeDef, "!=")
		isGlob := false

		if strings.HasSuffix(rangeSpec, ".*") {
			isGlob = true
			rangeSpec = strings.TrimSuffix(rangeSpec, ".*")
		}
		if !valid(rangeSpec) {
			return false, errors.New("Range spec can not be parsed")
		}

		r := newVersion(rangeSpec)
		if len(r.Local) > 0 {
			return false, errors.New("Range spec specified local part, which is not permitted")
		}

		if isGlob {
			r.Release = append(r.Release, STAR_MATCH)
		}

		return compareVersions(v, r) != EQUAL, nil
	} else if strings.HasPrefix(rangeDef, ">=") {
		rangeSpec := strings.TrimPrefix(rangeDef, ">=")
		if !valid(rangeSpec) {
			return false, errors.New("Range spec can not be parsed")
		}

		r := newVersion(rangeSpec)
		if len(r.Local) > 0 {
			return false, errors.New("Range spec specified local part, which is not permitted")
		}

		return compareVersions(v, r) > LESS, nil
	} else if strings.HasPrefix(rangeDef, "<=") {
		rangeSpec := strings.TrimPrefix(rangeDef, "<=")
		if !valid(rangeSpec) {
			return false, errors.New("Range spec can not be parsed")
		}

		r := newVersion(rangeSpec)
		if len(r.Local) > 0 {
			return false, errors.New("Range spec specified local part, which is not permitted")
		}

		return compareVersions(v, r) < GREATER, nil
	} else if strings.HasPrefix(rangeDef, ">") {
		rangeSpec := strings.TrimPrefix(rangeDef, ">")
		if !valid(rangeSpec) {
			return false, errors.New("Range spec can not be parsed")
		}

		r := newVersion(rangeSpec)
		if len(r.Local) > 0 {
			return false, errors.New("Range spec specified local part, which is not permitted")
		}

		if r.PostRelease == -1 {
			v.PostRelease = -1
		}

		return compareVersions(v, r) == GREATER, nil
	} else if strings.HasPrefix(rangeDef, "<") {
		rangeSpec := strings.TrimPrefix(rangeDef, "<")
		if !valid(rangeSpec) {
			return false, errors.New("Range spec can not be parsed")
		}

		r := newVersion(rangeSpec)
		if len(r.Local) > 0 {
			return false, errors.New("Range spec specified local part, which is not permitted")
		}

		if r.PreType == FINAL {
			v.PreType = FINAL
			v.PreRelease = -1
		}

		return compareVersions(v, r) == LESS, nil
	} else {
		return false, errors.New("Range spec can not be parsed")
	}
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
	if strings.HasPrefix(rangeDef, "===") {
		rangeSpec := strings.TrimSpace(strings.TrimPrefix(rangeDef, "==="))
		return str == rangeSpec, nil
	}

	var v version

	if str == versionfmt.MinVersion {
		v = version{Epoch: MinInt}
	} else if str == versionfmt.MaxVersion {
		v = version{Epoch: MaxInt}
	} else if !valid(str) {
		return false, errors.New("Version string can not be parsed")
	} else {
		v = newVersion(str)
		v.Local = []string{}
	}

	for _, part := range strings.Split(rangeDef, ",") {
		partResult, err := evaluateRangePart(v, part)
		if err != nil {
			return false, err
		}

		if !partResult {
			return false, nil
		}
	}

	return true, nil
}

func (p parser) GetFixedIn(fixedIn string) (string, error) {
	// this appears to be unused, and the expected semantics aren't clear
	return fixedIn, nil
}

func init() {
	versionRegex = regexp.MustCompile("(?i)" + PEP440Regex)
	versionfmt.RegisterParser(ParserName, parser{})
}
