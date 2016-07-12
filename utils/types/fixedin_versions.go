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

package types

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode"
)

type Operator string

const (
	OpNotEqual     Operator = "!="
	OpLessThan     Operator = "<"
	OpLessEqual    Operator = "<="
	OpEqualTo      Operator = "=="
	OpGreaterEqual Operator = ">="
	OpGreaterThan  Operator = ">"
)

type FixedInVersions struct {
	fivs [][]operVersion
}

type operVersion struct {
	oper    Operator
	version Version
}

type ovState string

const (
	ovStateInit    ovState = "init"
	ovStateOper    ovState = "operation"
	ovStateVersion ovState = "version"
)

func isOperChar(ch rune) bool {
	return ch == '>' || ch == '<' || ch == '='
}

func getOperator(str string) (oper Operator, error error) {
	switch str {
	case "!=":
	case "<":
	case "<=":
	case "==":
	case ">=":
	case ">":
	default:
		return oper, fmt.Errorf("Invalid operator: '%s'", str)
	}

	return Operator(str), nil
}

func getFixedinVersion(content string) (ovs []operVersion, err error) {
	state := ovStateInit
	begin := 0
	var ov operVersion
	for i, ch := range content {
		if unicode.IsSpace(ch) {
			continue
		}
		switch state {
		case ovStateInit:
			if isOperChar(ch) {
				state = ovStateOper
			} else {
				// Default to '>='
				ov.oper = OpGreaterEqual
				state = ovStateVersion
			}
			begin = i
		case ovStateOper:
			if !isOperChar(ch) {
				state = ovStateVersion
				if ov.oper, err = getOperator(strings.TrimSpace(content[begin:i])); err != nil {
					return nil, err
				}
				begin = i
			}
		case ovStateVersion:
			if isOperChar(ch) {
				state = ovStateOper
				if ov.version, err = NewVersion(strings.TrimSpace(content[begin:i])); err != nil {
					return nil, err
				}
				ovs = append(ovs, ov)
				begin = i
			}
		}
	}
	if state == ovStateVersion {
		if ov.version, err = NewVersion(strings.TrimSpace(content[begin:len(content)])); err != nil {
			return nil, err
		}
		ovs = append(ovs, ov)
	}

	if len(ovs) == 0 {
		err = fmt.Errorf("Failed to parse '%s'", content)
	}

	return
}

func (ov operVersion) patched(version Version) bool {
	val := version.Compare(ov.version)
	switch ov.oper {
	case OpNotEqual:
		return val != 0
	case OpLessThan:
		return val < 0
	case OpLessEqual:
		return val <= 0
	case OpEqualTo:
		return val == 0
	case OpGreaterEqual:
		return val >= 0
	case OpGreaterThan:
		return val > 0
	}

	//Cannot get here
	return false
}

// String returns the string representation of a FixedInVersions
func (fivs FixedInVersions) String() (s string) {
	firstFiv := false
	for _, fiv := range fivs.fivs {
		if !firstFiv {
			firstFiv = true
		} else {
			s += " || "
		}

		firstOV := false
		for _, ov := range fiv {
			if !firstOV {
				firstOV = true
			} else {
				s += " "
			}
			s += string(ov.oper) + ov.version.String()
		}
	}

	return
}

func (fivs FixedInVersions) MarshalJSON() ([]byte, error) {
	return json.Marshal(fivs.String())
}

func (fivs *FixedInVersions) UnmarshalJSON(b []byte) (err error) {
	var str string
	json.Unmarshal(b, &str)
	vp := NewFixedInVersionsUnsafe(str)
	*fivs = vp
	return
}

func (fivs *FixedInVersions) Scan(value interface{}) (err error) {
	val, ok := value.([]byte)
	if !ok {
		return errors.New("could not scan a Version from a non-string input")
	}
	*fivs, err = NewFixedInVersions(string(val))
	return
}

func (fivs *FixedInVersions) Value() (driver.Value, error) {
	return fivs.String(), nil
}

func (fivs FixedInVersions) Affected(version Version) bool {
	for _, fiv := range fivs.fivs {
		affected := false
		for _, ov := range fiv {
			if !ov.patched(version) {
				affected = true
				break
			}
		}
		if !affected {
			return false
		}
	}

	return true
}

func NewFixedInVersionsFromOV(oper Operator, version Version) FixedInVersions {
	var fivs FixedInVersions
	var fiv []operVersion

	fiv = append(fiv, operVersion{oper, version})
	fivs.fivs = append(fivs.fivs, fiv)

	return fivs
}

func NewFixedInVersions(str string) (FixedInVersions, error) {
	var fivs FixedInVersions
	for _, ovsStr := range strings.Split(str, "||") {
		if fiv, err := getFixedinVersion(ovsStr); err == nil {
			fivs.fivs = append(fivs.fivs, fiv)
		} else {
			return fivs, err
		}
	}

	return fivs, nil
}

func NewFixedInVersionsUnsafe(str string) FixedInVersions {
	fivs, _ := NewFixedInVersions(str)
	return fivs
}
