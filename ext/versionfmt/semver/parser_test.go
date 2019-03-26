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

package semver

import (
	"github.com/stretchr/testify/assert"
	"testing"

	"github.com/coreos/clair/ext/versionfmt"
)

func TestValid(t *testing.T) {
	p := parser{}
	cases := []struct {
		str      string
		expected bool
	}{
		// Min/max logic
		{versionfmt.MinVersion, true},
		{versionfmt.MaxVersion, true},

		// Happy path
		{"1.0.0", true},
		// Pre-release
		{"1.0.0-alpha", true},

		// Unhappy path
		{"major.minor.patch", false},

		// Build metadata
		{"1.0.0+foo.bar", true},
	}
	for _, c := range cases {
		v := p.Valid(c.str)

		assert.Equal(t, c.expected, v, "When parsing '%s'", c.str)
	}
}

func TestCompare(t *testing.T) {
	cases := []struct {
		v1       string
		expected int
		v2       string
		err      bool
	}{
		// Basic case
		{"1.0.0", EQUAL, "1.0.0", false},
		{"1.0.0", LESS, "2.0.0", false},

		// error handling
		{"invalid", EQUAL, "1.0.0", true},
		{"1.0.0", EQUAL, "invalid", true},

		// min/max logic
		{"1.0.0", GREATER, versionfmt.MinVersion, false},
		{versionfmt.MinVersion, LESS, "1.0.0", false},
		{"1.0.0", LESS, versionfmt.MaxVersion, false},
		{versionfmt.MaxVersion, GREATER, "1.0.0", false},
		{versionfmt.MinVersion, EQUAL, versionfmt.MinVersion, false},
		{versionfmt.MaxVersion, EQUAL, versionfmt.MaxVersion, false},

		// pre-release handling
		{"1.0.0", GREATER, "1.0.0-a", false},
		{"1.0.0-2", LESS, "1.0.0-a", false},
		{"1.0.0-alpha.2", GREATER, "1.0.0-alpha.1", false},
		{"1.0.0-alpha", LESS, "1.0.0-alpha.2", false},
		{"1.0.0-alpha", LESS, "1.0.0-beta", false},

		// build metadata
		{"1.0.0+0", EQUAL, "1.0.0", false},
		{"1.0.0+0.1", EQUAL, "1.0.0+0.2", false},
	}

	var (
		p   parser
		cmp int
		err error
	)
	for _, c := range cases {
		cmp, err = p.Compare(c.v1, c.v2)
		if c.err {
			assert.Error(t, err, "When comparing '%s' and '%s", c.v1, c.v2)
		} else {
			assert.Nil(t, err, "When comparing '%s' and '%s", c.v1, c.v2)
		}

		assert.Equal(t, c.expected, cmp, "%s vs. %s, = %d, expected %d", c.v1, c.v2, cmp, c.expected)
	}
}

func TestInRange(t *testing.T) {
	cases := []struct {
		v        string
		r        string
		expected bool
		err      bool
	}{
		// error handling
		{"invalid", "1.0.0", false, true},
		{"1.0.0", "some nonsense", false, true},
		{"1.0.0", ">= 1.6", false, true},

		// exact match
		{"1.1.0", "1.1.0", true, false},

		// *
		{"1.1.0", "*", true, false},

		// ordering
		{"1.1.0", "<= 1.1.0", true, false},
		{"1.0.0", "<= 1.1.0", true, false},
		{"1.2.0", "<= 1.1.0", false, false},
		{"1.1.0", ">= 1.1.0", true, false},
		{"1.0.0", ">= 1.1.0", false, false},
		{"1.2.0", ">= 1.1.0", true, false},
		{"1.1.0", "< 1.1.0", false, false},
		{"1.0.0", "< 1.1.0", true, false},
		{"1.2.0", "< 1.1.0", false, false},
		{"1.1.0", "> 1.1.0", false, false},
		{"1.0.0", "> 1.1.0", false, false},
		{"1.2.0", "> 1.1.0", true, false},

		// tilde
		{"1.1.0", "~1.1.0", true, false},
		{"1.1.2", "~1.1.0", true, false},
		{"1.2.0", "~1.1.0", false, false},

		// caret
		{"1.1.0", "^1.1.0", true, false},
		{"1.2.0", "^1.1.0", true, false},
		{"2.1.0", "^1.1.0", false, false},

		// multiple version specifiers
		{"1.1.0", ">= 1.1.0 < 2.0.0", true, false},
		{"1.0.0", ">= 1.1.0 < 2.0.0", false, false},
		{"2.1.0", ">= 1.1.0 < 2.0.0", false, false},
		{"2.14.0", "<= 2.15.0 || >= 3.0.0 <= 3.8.2", true, false},
		{"3.8.1", "<= 2.15.0 || >= 3.0.0 <= 3.8.2", true, false},

		// whitespace flexibility
		{"1.1.0", ">=1.1.0 <  2.0.0", true, false},

		// min/max logic
		{versionfmt.MinVersion, "< 0.0.0", true, false},
		{versionfmt.MaxVersion, ">= 1.0.0", true, false},
		{versionfmt.MaxVersion, ">= 1.0.0 < 2.0.0", false, false},
	}

	var (
		p   parser
		res bool
		err error
	)
	for _, c := range cases {
		res, err = p.InRange(c.v, c.r)
		if c.err {
			assert.Error(t, err, "When checking '%s' in range of '%s", c.v, c.r)
		} else {
			assert.Nil(t, err, "When checking '%s' in range of '%s", c.v, c.r)
		}

		assert.Equal(t, c.expected, res, "%s in range of %s, got %t, expected %t", c.v, c.r, res, c.expected)
	}
}
