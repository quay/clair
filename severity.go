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

package clair

import (
	"database/sql/driver"
	"errors"
	"strings"
)

var (
	// ErrFailedToParseSeverity is the error returned when a severity could not
	// be parsed from a string.
	ErrFailedToParseSeverity = errors.New("failed to parse Severity from input")
)

// Severity defines a standard scale for measuring the severity of a
// vulnerability.
type Severity string

const (
	// Unknown is either a security problem that has not been
	// assigned to a priority yet or a priority that our system
	// did not recognize.
	Unknown Severity = "Unknown"

	// Negligible is technically a security problem, but is
	// only theoretical in nature, requires a very special
	// situation, has almost no install base, or does no real
	// damage. These tend not to get backport from upstreams,
	// and will likely not be included in security updates unless
	// there is an easy fix and some other issue causes an update.
	Negligible Severity = "Negligible"

	// Low is a security problem, but is hard to
	// exploit due to environment, requires a user-assisted
	// attack, a small install base, or does very little damage.
	// These tend to be included in security updates only when
	// higher priority issues require an update, or if many
	// low priority issues have built up.
	Low Severity = "Low"

	// Medium is a real security problem, and is exploitable
	// for many people. Includes network daemon denial of service
	// attacks, cross-site scripting, and gaining user privileges.
	// Updates should be made soon for this priority of issue.
	Medium Severity = "Medium"

	// High is a real problem, exploitable for many people in a default
	// installation. Includes serious remote denial of services,
	// local root privilege escalations, or data loss.
	High Severity = "High"

	// Critical is a world-burning problem, exploitable for nearly all people
	// in a default installation of Linux. Includes remote root
	// privilege escalations, or massive data loss.
	Critical Severity = "Critical"

	// Defcon1 is a Critical problem which has been manually highlighted by
	// the team. It requires an immediate attention.
	Defcon1 Severity = "Defcon1"
)

// Severities lists all known severities, ordered from lowest to highest.
var Severities = []Severity{
	Unknown,
	Negligible,
	Low,
	Medium,
	High,
	Critical,
	Defcon1,
}

// NewSeverity attempts to parse a string into a standard Severity value.
func NewSeverity(s string) (Severity, error) {
	for _, ss := range Severities {
		if strings.EqualFold(s, string(ss)) {
			return ss, nil
		}
	}

	return Unknown, ErrFailedToParseSeverity
}

// Compare determines the equality of two severities.
//
// If the severities are equal, returns 0.
// If the receiever is less, returns -1.
// If the receiver is greater, returns 1.
func (s Severity) Compare(s2 Severity) int {
	var i1, i2 int

	for i1 = 0; i1 < len(Severities); i1 = i1 + 1 {
		if s == Severities[i1] {
			break
		}
	}
	for i2 = 0; i2 < len(Severities); i2 = i2 + 1 {
		if s2 == Severities[i2] {
			break
		}
	}

	return i1 - i2
}

// Scan implements the database/sql.Scanner interface.
func (s *Severity) Scan(value interface{}) error {
	val, ok := value.([]byte)
	if !ok {
		return errors.New("could not scan a Severity from a non-string input")
	}

	var err error
	*s, err = NewSeverity(string(val))
	if err != nil {
		return err
	}

	return nil
}

// Value implements the database/sql/driver.Valuer interface.
func (s Severity) Value() (driver.Value, error) {
	return string(s), nil
}
