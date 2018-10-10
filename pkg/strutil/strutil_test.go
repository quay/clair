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

package strutil

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSubstring(t *testing.T) {
	for _, test := range [...]struct {
		in    string
		start int
		end   int

		out string
	}{
		{"", 0, 1, ""}, {"", 0, 0, ""}, {"", -1, -1, ""}, {"1", 1, 0, ""},
		{"1", 1, 1, ""}, {"1", 0, 1, "1"}, {"1", 0, 2, ""},
	} {
		require.Equal(t, test.out, Substring(test.in, test.start, test.end))
	}
}

func TestStringComparison(t *testing.T) {
	cmp := Difference([]string{"a", "b", "b", "a"}, []string{"a", "c"})
	assert.Len(t, cmp, 1)
	assert.NotContains(t, cmp, "a")
	assert.Contains(t, cmp, "b")

	cmp = Intersect([]string{"a", "a", "b", "c"}, []string{"a", "c", "c"})
	assert.Len(t, cmp, 2)
	assert.NotContains(t, cmp, "b")
	assert.Contains(t, cmp, "a")
	assert.Contains(t, cmp, "c")
}
