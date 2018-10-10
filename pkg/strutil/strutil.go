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
	"regexp"

	set "github.com/deckarep/golang-set"
)

var urlParametersRegexp = regexp.MustCompile(`(\?|\&)([^=]+)\=([^ &]+)`)

func convertToSet(X []string) set.Set {
	s := set.NewSet()
	for _, x := range X {
		s.Add(x)
	}
	return s
}

func setToStringSlice(s set.Set) []string {
	strs := make([]string, 0, s.Cardinality())
	for _, str := range s.ToSlice() {
		strs = append(strs, str.(string))
	}

	return strs
}

// Difference returns the strings that are present in X but not in Y.
func Difference(X, Y []string) []string {
	x := convertToSet(X)
	y := convertToSet(Y)
	return setToStringSlice(x.Difference(y))
}

// Intersect returns the strings that are present in both X and Y.
func Intersect(X, Y []string) []string {
	x := convertToSet(X)
	y := convertToSet(Y)
	return setToStringSlice(x.Intersect(y))
}

// CleanURL removes all parameters from an URL.
func CleanURL(str string) string {
	return urlParametersRegexp.ReplaceAllString(str, "")
}

// Substring returns a substring by [start, end). If start or end are out
// of bound, it returns "".
func Substring(s string, start, end int) string {
	if start > len(s) || start < 0 || end > len(s) || end < 0 || start >= end {
		return ""
	}

	return s[start:end]
}
