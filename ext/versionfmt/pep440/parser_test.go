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

package pep440

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

		// Unhappy path
		{"major.minor.patch", false},

		// Do not allow * in plain versions
		{"1.0.*", false},
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

		// some different lengths
		{"1", EQUAL, "1.0.0", false},
		{"1.0", LESS, "1.0.0.1", false},

		// Epoch handling
		{"1!1.0.0", GREATER, "1.0.0", false},
		{"1!1.0.0", LESS, "2!1.0.0", false},

		// pre-release handling
		{"1.0.0", GREATER, "1.0.0a", false},
		{"1.0.0", GREATER, "1.0.0rc4", false},
		{"1.0.0a1", GREATER, "1.0.0a", false},
		{"1.0.0a", LESS, "1.0.0b", false},
		{"1.0.0b", LESS, "1.0.0rc", false},

		// case-insensitivity
		{"1.0RC1", EQUAL, "1.0.0rc1", false},

		// post-release handling
		{"1.0.0.post", GREATER, "1.0.0", false},
		{"1.0.0.post2", GREATER, "1.0.0post", false},
		{"1.0.0-2", EQUAL, "1.0.0post2", false},
		{"1.0.0a1.post", GREATER, "1.0.0a1", false},
		{"1.0.0a1.post2", GREATER, "1.0.0a1.post1", false},

		// dev releases
		{"1.0.0.dev", LESS, "1.0.0", false},
		{"1.0.0.dev", LESS, "1.0.0a", false},

		// local releases
		{"1.0.0+0", GREATER, "1.0.0", false},
		{"1.0.0+0.0", GREATER, "1.0.0+0", false},
		{"1.0.0+0.1", EQUAL, "1.0.0+0_1", false},
		{"1.0.0+ubuntu", LESS, "1.0.0+0", false},
		{"1.0.0+aardvark", LESS, "1.0.0+zebra", false},
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
		{"invalid", "^1.0.0", false, true},
		{"1.0.0", "some nonsense", false, true},
		{"1.0.0", ">= 1.*", false, true},

		// "compatible release" clause
		{"1.2.3", "~= 1.2", true, false},
		{"1.2.3", "~= 1.1", true, false},
		{"2.2.3", "~= 1.1", false, false},
		{"1.2.3", "~= 1.1.0", false, false},
		{"1.2.3", "~= 1.3", false, false},

		// "version matching" clause
		{"1.1", "== 1.1", true, false},
		{"1.1", "== 1.1.0", true, false},
		{"1.1", "== 1.1.dev1", false, false},
		{"1.1", "== 1.1a1", false, false},
		{"1.1", "== 1.1post1", false, false},
		{"1.1+ubuntu_1", "== 1.1", true, false},

		// "version exclusion" clause
		{"1.1.post1", "!= 1.1", true, false},
		{"1.1.post1", "!= 1.1.post1", false, false},

		// trailing *
		{"1.1", "== 1.1.*", true, false},
		{"1.1a1", "== 1.1.*", true, false},
		{"1.1.post1", "== 1.1.*", true, false},
		{"1.1.post1", "!= 1.1.*", false, false},
		{"1.1", "== 1.*.0", false, true},
		{"1.1", "== 1.*.a1", false, true},
		{"1.1", "== 1.*.post1", false, true},

		// "inclusive ordered comparison" clause
		{"1.1", "<= 1.1", true, false},
		{"1.0", "<= 1.1", true, false},
		{"1.2", "<= 1.1", false, false},
		{"1.1", ">= 1.1", true, false},
		{"1.0", ">= 1.1", false, false},
		{"1.2", ">= 1.1", true, false},

		// "exclusive ordered comparison" clause
		{"1.1", "< 1.1", false, false},
		{"1.0", "< 1.1", true, false},
		{"1.2", "< 1.1", false, false},
		{"1.1", "> 1.1", false, false},
		{"1.0", "> 1.1", false, false},
		{"1.2", "> 1.1", true, false},
		{"1.1.post1", "> 1.1", false, false},
		{"1.1.post2", "> 1.1.post1", true, false},
		{"1.1.pre1", "< 1.1", false, false},
		{"1.1.pre1", "< 1.1.pre2", true, false},

		// "arbitrary equality" clause
		{"foo", "=== foo", true, false},
		{"foo", "=== bar", false, false},

		// multiple version specifiers
		{"1.1", ">= 1.1, < 2.0.0", true, false},

		// whitespace flexibility
		{"1.1", "==1.1", true, false},
		{"1.1", ">=1.1,<  2.0.0", true, false},

		// min/max logic
		{versionfmt.MinVersion, "< 0.0.0", true, false},
		{versionfmt.MaxVersion, ">= 1.0.0", true, false},
		{versionfmt.MaxVersion, ">= 1.0.0, < 2.0", false, false},
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
