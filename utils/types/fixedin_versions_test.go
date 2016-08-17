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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFixedInVersions(t *testing.T) {
	invalid_version := "3.1.3 < 4.0.0 || >=  "
	fivs, err := NewFixedInVersions(invalid_version)
	assert.Error(t, err, "Failed to parse '%s'", ">=")

	invalid_version = "3.1.3 < ab.0.0 || >=  "
	fivs, err = NewFixedInVersions(invalid_version)
	assert.Error(t, err, "Failed to parse '%s'", ">=")

	valid_version := "3.1.3"
	fivs, err = NewFixedInVersions(valid_version)
	assert.Nil(t, err)

	valid_version = ">=3.1.3 <4.0.0 || >=4.1.1"
	fivs, err = NewFixedInVersions(valid_version)
	assert.Nil(t, err)
	assert.Equal(t, strings.Replace(fivs.String(), " ", "", -1), strings.Replace(valid_version, " ", "", -1))

	for _, fiv := range fivs.fivs {
		if len(fiv) == 1 {
			assert.Equal(t, OpGreaterEqual, fiv[0].oper)
			assert.Equal(t, NewVersionUnsafe("4.1.1"), fiv[0].version)
		} else {
			for _, ov := range fiv {
				if ov.oper == OpGreaterEqual {
					assert.Equal(t, NewVersionUnsafe("3.1.3"), ov.version)
				} else if ov.oper == OpLessThan {
					assert.Equal(t, NewVersionUnsafe("4.0.0"), ov.version)
				}
			}
		}
	}

	cases := []struct {
		version  string
		expected bool
	}{
		{"4.2", false},
		{"4.0.0", true},
		{"3.1.3", false},
		{"3.1.2", true},
	}
	for _, c := range cases {
		assert.Equal(t, fivs.Affected(NewVersionUnsafe(c.version)), c.expected)
	}
}
