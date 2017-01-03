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

package rpm

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	LESS    = -1
	EQUAL   = 0
	GREATER = 1
)

func TestParse(t *testing.T) {
	cases := []struct {
		str string
		ver version
		err bool
	}{
		// Test 0
		{"0", version{epoch: 0, version: "0", release: ""}, false},
		{"0:0", version{epoch: 0, version: "0", release: ""}, false},
		{"0:0-", version{epoch: 0, version: "0", release: ""}, false},
		{"0:0-0", version{epoch: 0, version: "0", release: "0"}, false},
		{"0:0.0-0.0", version{epoch: 0, version: "0.0", release: "0.0"}, false},
		// Test epoched
		{"1:0", version{epoch: 1, version: "0", release: ""}, false},
		{"5:1", version{epoch: 5, version: "1", release: ""}, false},
		// Test multiple hypens
		{"0:0-0-0", version{epoch: 0, version: "0", release: "0-0"}, false},
		{"0:0-0-0-0", version{epoch: 0, version: "0", release: "0-0-0"}, false},
		// Test multiple colons
		{"0:0:0-0", version{epoch: 0, version: "0:0", release: "0"}, false},
		{"0:0:0:0-0", version{epoch: 0, version: "0:0:0", release: "0"}, false},
		// Test multiple hyphens and colons
		{"0:0:0-0-0", version{epoch: 0, version: "0:0", release: "0-0"}, false},
		{"0:0-0:0-0", version{epoch: 0, version: "0", release: "0:0-0"}, false},
		// Test version with leading and trailing spaces
		{"  	0:0-1", version{epoch: 0, version: "0", release: "1"}, false},
		{"0:0-1	  ", version{epoch: 0, version: "0", release: "1"}, false},
		{"	  0:0-1  	", version{epoch: 0, version: "0", release: "1"}, false},
		// Test empty version
		{"", version{}, true},
		{" ", version{}, true},
		{"0:", version{}, true},
		// Test version with embedded spaces
		{"0:0 0-1", version{}, true},
		// Test version with negative epoch
		{"-1:0-1", version{}, true},
		// Test invalid characters in epoch
		{"a:0-0", version{}, true},
		{"A:0-0", version{}, true},
		// Test version not starting with a digit
		{"0:abc3-0", version{epoch: 0, version: "abc3", release: "0"}, false},
	}
	for _, c := range cases {
		v, err := newVersion(c.str)

		if c.err {
			assert.Error(t, err, "When parsing '%s'", c.str)
		} else {
			assert.Nil(t, err, "When parsing '%s'", c.str)
		}
		assert.Equal(t, c.ver, v, "When parsing '%s'", c.str)
	}
}

func TestParseAndCompare(t *testing.T) {
	cases := []struct {
		v1       string
		expected int
		v2       string
	}{
		// Oracle Linux corner cases.
		{"2.9.1-6.0.1.el7_2.3", GREATER, "2.9.1-6.el7_2.3"},
		{"3.10.0-327.28.3.el7", GREATER, "3.10.0-327.el7"},
		{"3.14.3-23.3.el6_8", GREATER, "3.14.3-23.el6_7"},
		{"2.23.2-22.el7_1", LESS, "2.23.2-22.el7_1.1"},

		// Tests imported from tests/rpmvercmp.at
		{"1.0", EQUAL, "1.0"},
		{"1.0", LESS, "2.0"},
		{"2.0", GREATER, "1.0"},
		{"2.0.1", EQUAL, "2.0.1"},
		{"2.0", LESS, "2.0.1"},
		{"2.0.1", GREATER, "2.0"},
		{"2.0.1a", EQUAL, "2.0.1a"},
		{"2.0.1a", GREATER, "2.0.1"},
		{"2.0.1", LESS, "2.0.1a"},
		{"5.5p1", EQUAL, "5.5p1"},
		{"5.5p1", LESS, "5.5p2"},
		{"5.5p2", GREATER, "5.5p1"},
		{"5.5p10", EQUAL, "5.5p10"},
		{"5.5p1", LESS, "5.5p10"},
		{"5.5p10", GREATER, "5.5p1"},
		{"10xyz", LESS, "10.1xyz"},
		{"10.1xyz", GREATER, "10xyz"},
		{"xyz10", EQUAL, "xyz10"},
		{"xyz10", LESS, "xyz10.1"},
		{"xyz10.1", GREATER, "xyz10"},
		{"xyz.4", EQUAL, "xyz.4"},
		{"xyz.4", LESS, "8"},
		{"8", GREATER, "xyz.4"},
		{"xyz.4", LESS, "2"},
		{"2", GREATER, "xyz.4"},
		{"5.5p2", LESS, "5.6p1"},
		{"5.6p1", GREATER, "5.5p2"},
		{"5.6p1", LESS, "6.5p1"},
		{"6.5p1", GREATER, "5.6p1"},
		{"6.0.rc1", GREATER, "6.0"},
		{"6.0", LESS, "6.0.rc1"},
		{"10b2", GREATER, "10a1"},
		{"10a2", LESS, "10b2"},
		{"1.0aa", EQUAL, "1.0aa"},
		{"1.0a", LESS, "1.0aa"},
		{"1.0aa", GREATER, "1.0a"},
		{"10.0001", EQUAL, "10.0001"},
		{"10.0001", EQUAL, "10.1"},
		{"10.1", EQUAL, "10.0001"},
		{"10.0001", LESS, "10.0039"},
		{"10.0039", GREATER, "10.0001"},
		{"4.999.9", LESS, "5.0"},
		{"5.0", GREATER, "4.999.9"},
		{"20101121", EQUAL, "20101121"},
		{"20101121", LESS, "20101122"},
		{"20101122", GREATER, "20101121"},
		{"2_0", EQUAL, "2_0"},
		{"2.0", EQUAL, "2_0"},
		{"2_0", EQUAL, "2.0"},
		{"a", EQUAL, "a"},
		{"a+", EQUAL, "a+"},
		{"a+", EQUAL, "a_"},
		{"a_", EQUAL, "a+"},
		{"+a", EQUAL, "+a"},
		{"+a", EQUAL, "_a"},
		{"_a", EQUAL, "+a"},
		{"+_", EQUAL, "+_"},
		{"_+", EQUAL, "+_"},
		{"_+", EQUAL, "_+"},
		{"+", EQUAL, "_"},
		{"_", EQUAL, "+"},
		{"1.0~rc1", EQUAL, "1.0~rc1"},
		{"1.0~rc1", LESS, "1.0"},
		{"1.0", GREATER, "1.0~rc1"},
		{"1.0~rc1", LESS, "1.0~rc2"},
		{"1.0~rc2", GREATER, "1.0~rc1"},
		{"1.0~rc1~git123", EQUAL, "1.0~rc1~git123"},
		{"1.0~rc1~git123", LESS, "1.0~rc1"},
		{"1.0~rc1", GREATER, "1.0~rc1~git123"},
	}

	var (
		p   parser
		cmp int
		err error
	)
	for _, c := range cases {
		cmp, err = p.Compare(c.v1, c.v2)
		assert.Nil(t, err)
		assert.Equal(t, c.expected, cmp, "%s vs. %s, = %d, expected %d", c.v1, c.v2, cmp, c.expected)

		cmp, err = p.Compare(c.v2, c.v1)
		assert.Nil(t, err)
		assert.Equal(t, -c.expected, cmp, "%s vs. %s, = %d, expected %d", c.v2, c.v1, cmp, -c.expected)
	}
}
