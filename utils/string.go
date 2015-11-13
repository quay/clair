// Copyright 2015 quay-sec authors
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

package utils

import (
	"crypto/sha1"
	"encoding/hex"
	"regexp"
)

var urlParametersRegexp = regexp.MustCompile(`(\?|\&)([^=]+)\=([^ &]+)`)

// Hash returns an unique hash of the given string
func Hash(str string) string {
	h := sha1.New()
	h.Write([]byte(str))
	bs := h.Sum(nil)
	return hex.EncodeToString(bs)
}

// CleanURL removes all parameters from an URL
func CleanURL(str string) string {
	return urlParametersRegexp.ReplaceAllString(str, "")
}

// Contains looks for a string into an array of strings and returns whether
// the string exists
func Contains(needle string, haystack []string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

// CompareStringLists returns the strings which are present in X but not in Y
func CompareStringLists(X, Y []string) []string {
	m := make(map[string]int)

	for _, y := range Y {
		m[y] = 1
	}

	diff := []string{}
	for _, x := range X {
		if m[x] > 0 {
			continue
		}

		diff = append(diff, x)
		m[x] = 1
	}

	return diff
}
