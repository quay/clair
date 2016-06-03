// Copyright 2015 clair authors
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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	LESS    = -1
	EQUAL   = 0
	GREATER = 1
)

func TestCompareSimpleVersion(t *testing.T) {
	cases := []struct {
		v1       Version
		expected int
		v2       Version
	}{
		{Version{}, EQUAL, Version{}},
		{Version{epoch: 1}, LESS, Version{epoch: 2}},
		{Version{epoch: 0, version: "1", revision: "1"}, LESS, Version{epoch: 0, version: "2", revision: "1"}},
		{Version{epoch: 0, version: "a", revision: "0"}, LESS, Version{epoch: 0, version: "b", revision: "0"}},
		{Version{epoch: 0, version: "1", revision: "1"}, LESS, Version{epoch: 0, version: "1", revision: "2"}},
		{Version{epoch: 0, version: "0", revision: "0"}, EQUAL, Version{epoch: 0, version: "0", revision: "0"}},
		{Version{epoch: 0, version: "0", revision: "00"}, EQUAL, Version{epoch: 0, version: "00", revision: "0"}},
		{Version{epoch: 1, version: "2", revision: "3"}, EQUAL, Version{epoch: 1, version: "2", revision: "3"}},
		{Version{epoch: 0, version: "0", revision: "a"}, LESS, Version{epoch: 0, version: "0", revision: "b"}},
		{MinVersion, LESS, MaxVersion},
		{MinVersion, LESS, Version{}},
		{MinVersion, LESS, Version{version: "0"}},
		{MaxVersion, GREATER, Version{}},
		{MaxVersion, GREATER, Version{epoch: 9999999, version: "9999999", revision: "9999999"}},
	}

	for _, c := range cases {
		cmp := c.v1.Compare(c.v2)
		assert.Equal(t, c.expected, cmp, "%s vs. %s, = %d, expected %d", c.v1, c.v2, cmp, c.expected)

		cmp = c.v2.Compare(c.v1)
		assert.Equal(t, -c.expected, cmp, "%s vs. %s, = %d, expected %d", c.v2, c.v1, cmp, -c.expected)
	}
}

func TestParse(t *testing.T) {
	cases := []struct {
		str string
		ver Version
		err bool
	}{
		// Test 0
		{"0", Version{epoch: 0, version: "0", revision: ""}, false},
		{"0:0", Version{epoch: 0, version: "0", revision: ""}, false},
		{"0:0-", Version{epoch: 0, version: "0", revision: ""}, false},
		{"0:0-0", Version{epoch: 0, version: "0", revision: "0"}, false},
		{"0:0.0-0.0", Version{epoch: 0, version: "0.0", revision: "0.0"}, false},
		// Test epoched
		{"1:0", Version{epoch: 1, version: "0", revision: ""}, false},
		{"5:1", Version{epoch: 5, version: "1", revision: ""}, false},
		// Test multiple hypens
		{"0:0-0-0", Version{epoch: 0, version: "0-0", revision: "0"}, false},
		{"0:0-0-0-0", Version{epoch: 0, version: "0-0-0", revision: "0"}, false},
		// Test multiple colons
		{"0:0:0-0", Version{epoch: 0, version: "0:0", revision: "0"}, false},
		{"0:0:0:0-0", Version{epoch: 0, version: "0:0:0", revision: "0"}, false},
		// Test multiple hyphens and colons
		{"0:0:0-0-0", Version{epoch: 0, version: "0:0-0", revision: "0"}, false},
		{"0:0-0:0-0", Version{epoch: 0, version: "0-0:0", revision: "0"}, false},
		// Test valid characters in version
		{"0:09azAZ.-+~:_-0", Version{epoch: 0, version: "09azAZ.-+~:_", revision: "0"}, false},
		// Test valid characters in debian revision
		{"0:0-azAZ09.+~_", Version{epoch: 0, version: "0", revision: "azAZ09.+~_"}, false},
		// Test version with leading and trailing spaces
		{"  	0:0-1", Version{epoch: 0, version: "0", revision: "1"}, false},
		{"0:0-1	  ", Version{epoch: 0, version: "0", revision: "1"}, false},
		{"	  0:0-1  	", Version{epoch: 0, version: "0", revision: "1"}, false},
		// Test empty version
		{"", Version{}, true},
		{" ", Version{}, true},
		{"0:", Version{}, true},
		// Test version with embedded spaces
		{"0:0 0-1", Version{}, true},
		// Test version with negative epoch
		{"-1:0-1", Version{}, true},
		// Test invalid characters in epoch
		{"a:0-0", Version{}, true},
		{"A:0-0", Version{}, true},
		// Test version not starting with a digit
		{"0:abc3-0", Version{}, true},
	}
	for _, c := range cases {
		v, err := NewVersion(c.str)

		if c.err {
			assert.Error(t, err, "When parsing '%s'", c.str)
		} else {
			assert.Nil(t, err, "When parsing '%s'", c.str)
		}
		assert.Equal(t, c.ver, v, "When parsing '%s'", c.str)
	}

	// Test invalid characters in version
	versym := []rune{'!', '#', '@', '$', '%', '&', '/', '|', '\\', '<', '>', '(', ')', '[', ']', '{', '}', ';', ',', '=', '*', '^', '\''}
	for _, r := range versym {
		_, err := NewVersion(strings.Join([]string{"0:0", string(r), "-0"}, ""))
		assert.Error(t, err, "Parsing with invalid character '%s' in version should have failed", string(r))
	}

	// Test invalid characters in revision
	versym = []rune{'!', '#', '@', '$', '%', '&', '/', '|', '\\', '<', '>', '(', ')', '[', ']', '{', '}', ':', ';', ',', '=', '*', '^', '\''}
	for _, r := range versym {
		_, err := NewVersion(strings.Join([]string{"0:0-", string(r)}, ""))
		assert.Error(t, err, "Parsing with invalid character '%s' in revision should have failed", string(r))
	}
}

func TestParseAndCompare(t *testing.T) {
	const LESS = -1
	const EQUAL = 0
	const GREATER = 1

	cases := []struct {
		v1       string
		expected int
		v2       string
	}{
		{"7.6p2-4", GREATER, "7.6-0"},
		{"1.0.3-3", GREATER, "1.0-1"},
		{"1.3", GREATER, "1.2.2-2"},
		{"1.3", GREATER, "1.2.2"},
		// Some properties of text strings
		{"0-pre", EQUAL, "0-pre"},
		{"0-pre", LESS, "0-pree"},
		{"1.1.6r2-2", GREATER, "1.1.6r-1"},
		{"2.6b2-1", GREATER, "2.6b-2"},
		{"98.1p5-1", LESS, "98.1-pre2-b6-2"},
		{"0.4a6-2", GREATER, "0.4-1"},
		{"1:3.0.5-2", LESS, "1:3.0.5.1"},
		// epochs
		{"1:0.4", GREATER, "10.3"},
		{"1:1.25-4", LESS, "1:1.25-8"},
		{"0:1.18.36", EQUAL, "1.18.36"},
		{"1.18.36", GREATER, "1.18.35"},
		{"0:1.18.36", GREATER, "1.18.35"},
		// Funky, but allowed, characters in upstream version
		{"9:1.18.36:5.4-20", LESS, "10:0.5.1-22"},
		{"9:1.18.36:5.4-20", LESS, "9:1.18.36:5.5-1"},
		{"9:1.18.36:5.4-20", LESS, " 9:1.18.37:4.3-22"},
		{"1.18.36-0.17.35-18", GREATER, "1.18.36-19"},
		// Junk
		{"1:1.2.13-3", LESS, "1:1.2.13-3.1"},
		{"2.0.7pre1-4", LESS, "2.0.7r-1"},
		// if a version includes a dash, it should be the debrev dash - policy says so
		{"0:0-0-0", GREATER, "0-0"},
		// do we like strange versions? Yes we like strange versions…
		{"0", EQUAL, "0"},
		{"0", EQUAL, "00"},
		// #205960
		{"3.0~rc1-1", LESS, "3.0-1"},
		// #573592 - debian policy 5.6.12
		{"1.0", EQUAL, "1.0-0"},
		{"0.2", LESS, "1.0-0"},
		{"1.0", LESS, "1.0-0+b1"},
		{"1.0", GREATER, "1.0-0~"},
		// "steal" the testcases from (old perl) cupt
		{"1.2.3", EQUAL, "1.2.3"},                           // identical
		{"4.4.3-2", EQUAL, "4.4.3-2"},                       // identical
		{"1:2ab:5", EQUAL, "1:2ab:5"},                       // this is correct...
		{"7:1-a:b-5", EQUAL, "7:1-a:b-5"},                   // and this
		{"57:1.2.3abYZ+~-4-5", EQUAL, "57:1.2.3abYZ+~-4-5"}, // and those too
		{"1.2.3", EQUAL, "0:1.2.3"},                         // zero epoch
		{"1.2.3", EQUAL, "1.2.3-0"},                         // zero revision
		{"009", EQUAL, "9"},                                 // zeroes…
		{"009ab5", EQUAL, "9ab5"},                           // there as well
		{"1.2.3", LESS, "1.2.3-1"},                          // added non-zero revision
		{"1.2.3", LESS, "1.2.4"},                            // just bigger
		{"1.2.4", GREATER, "1.2.3"},                         // order doesn't matter
		{"1.2.24", GREATER, "1.2.3"},                        // bigger, eh?
		{"0.10.0", GREATER, "0.8.7"},                        // bigger, eh?
		{"3.2", GREATER, "2.3"},                             // major number rocks
		{"1.3.2a", GREATER, "1.3.2"},                        // letters rock
		{"0.5.0~git", LESS, "0.5.0~git2"},                   // numbers rock
		{"2a", LESS, "21"},                                  // but not in all places
		{"1.3.2a", LESS, "1.3.2b"},                          // but there is another letter
		{"1:1.2.3", GREATER, "1.2.4"},                       // epoch rocks
		{"1:1.2.3", LESS, "1:1.2.4"},                        // bigger anyway
		{"1.2a+~bCd3", LESS, "1.2a++"},                      // tilde doesn't rock
		{"1.2a+~bCd3", GREATER, "1.2a+~"},                   // but first is longer!
		{"5:2", GREATER, "304-2"},                           // epoch rocks
		{"5:2", LESS, "304:2"},                              // so big epoch?
		{"25:2", GREATER, "3:2"},                            // 25 > 3, obviously
		{"1:2:123", LESS, "1:12:3"},                         // 12 > 2
		{"1.2-5", LESS, "1.2-3-5"},                          // 1.2 < 1.2-3
		{"5.10.0", GREATER, "5.005"},                        // preceding zeroes don't matters
		{"3a9.8", LESS, "3.10.2"},                           // letters are before all letter symbols
		{"3a9.8", GREATER, "3~10"},                          // but after the tilde
		{"1.4+OOo3.0.0~", LESS, "1.4+OOo3.0.0-4"},           // another tilde check
		{"2.4.7-1", LESS, "2.4.7-z"},                        // revision comparing
		{"1.002-1+b2", GREATER, "1.00"},                     // whatever...
	}

	for _, c := range cases {
		v1, err1 := NewVersion(c.v1)
		v2, err2 := NewVersion(c.v2)
		if assert.Nil(t, err1) && assert.Nil(t, err2) {
			cmp := v1.Compare(v2)
			assert.Equal(t, c.expected, cmp, "%s vs. %s, = %d, expected %d", c.v1, c.v2, cmp, c.expected)

			cmp = v2.Compare(v1)
			assert.Equal(t, -c.expected, cmp, "%s vs. %s, = %d, expected %d", c.v2, c.v1, cmp, -c.expected)
		}
	}
}

func TestVersionJson(t *testing.T) {
	v, _ := NewVersion("57:1.2.3abYZ+~-4-5")

	// Marshal
	json, err := v.MarshalJSON()
	assert.Nil(t, err)
	assert.Equal(t, "\""+v.String()+"\"", string(json))

	// Unmarshal
	var v2 Version
	v2.UnmarshalJSON(json)
	assert.Equal(t, v, v2)
}
