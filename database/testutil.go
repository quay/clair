// Copyright 2018 clair authors
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

package database

import (
	"encoding/json"
	"sort"
	"testing"

	"github.com/deckarep/golang-set"
	"github.com/stretchr/testify/assert"
)

// AssertDetectorsEqual asserts actual detectors are content wise equal to
// expected detectors regardless of the ordering.
func AssertDetectorsEqual(t *testing.T, expected, actual []Detector) bool {
	if len(expected) != len(actual) {
		return assert.Fail(t, "detectors are not equal", "expected: '%v', actual: '%v'", expected, actual)
	}

	sort.Slice(expected, func(i, j int) bool {
		return expected[i].String() < expected[j].String()
	})

	sort.Slice(actual, func(i, j int) bool {
		return actual[i].String() < actual[j].String()
	})

	for i := range expected {
		if expected[i] != actual[i] {
			return assert.Fail(t, "detectors are not equal", "expected: '%v', actual: '%v'", expected, actual)
		}
	}

	return true
}

// AssertAncestryEqual asserts actual ancestry equals to expected ancestry
// content wise.
func AssertAncestryEqual(t *testing.T, expected, actual *Ancestry) bool {
	if expected == actual {
		return true
	}

	if actual == nil || expected == nil {
		return assert.Equal(t, expected, actual)
	}

	if !assert.Equal(t, expected.Name, actual.Name) || !AssertDetectorsEqual(t, expected.By, actual.By) {
		return false
	}

	if assert.Equal(t, len(expected.Layers), len(actual.Layers)) {
		for index := range expected.Layers {
			if !AssertAncestryLayerEqual(t, &expected.Layers[index], &actual.Layers[index]) {
				return false
			}
		}
		return true
	}
	return false
}

// AssertAncestryLayerEqual asserts actual ancestry layer equals to expected
// ancestry layer content wise.
func AssertAncestryLayerEqual(t *testing.T, expected, actual *AncestryLayer) bool {
	if !assert.Equal(t, expected.Hash, actual.Hash) {
		return false
	}

	if !assert.Equal(t, len(expected.Features), len(actual.Features),
		"layer: %s\nExpected: %v\n  Actual: %v",
		expected.Hash, expected.Features, actual.Features,
	) {
		return false
	}

	// feature -> is in actual layer
	hitCounter := map[AncestryFeature]bool{}
	for _, f := range expected.Features {
		hitCounter[f] = false
	}

	// if there's no extra features and no duplicated features, since expected
	// and actual have the same length, their result must equal.
	for _, f := range actual.Features {
		v, ok := hitCounter[f]
		assert.True(t, ok, "unexpected feature %s", f)
		assert.False(t, v, "duplicated feature %s", f)
		hitCounter[f] = true
	}

	for f, visited := range hitCounter {
		assert.True(t, visited, "missing feature %s", f)
	}

	return true
}

// AssertElementsEqual asserts that content in actual equals to content in
// expected array regardless of ordering.
//
// Note: This function uses interface wise comparison.
func AssertElementsEqual(t *testing.T, expected, actual []interface{}) bool {
	counter := map[interface{}]bool{}
	for _, f := range expected {
		counter[f] = false
	}

	for _, f := range actual {
		v, ok := counter[f]
		if !assert.True(t, ok, "unexpected element %v\nExpected: %v\n  Actual: %v\n", f, expected, actual) {
			return false
		}

		if !assert.False(t, v, "duplicated element %v\nExpected: %v\n  Actual: %v\n", f, expected, actual) {
			return false
		}

		counter[f] = true
	}

	for f, visited := range counter {
		if !assert.True(t, visited, "missing feature %v\nExpected: %v\n  Actual: %v\n", f, expected, actual) {
			return false
		}
	}

	return true
}

// AssertFeaturesEqual asserts content in actual equals content in expected
// regardless of ordering.
func AssertFeaturesEqual(t *testing.T, expected, actual []Feature) bool {
	if assert.Len(t, actual, len(expected)) {
		has := map[Feature]bool{}
		for _, nf := range expected {
			has[nf] = false
		}

		for _, nf := range actual {
			has[nf] = true
		}

		for nf, visited := range has {
			if !assert.True(t, visited, nf.Name+" is expected") {
				return false
			}
			return true
		}
	}
	return false
}

// AssertLayerFeaturesEqual asserts content in actual equals to content in
// expected regardless of ordering.
func AssertLayerFeaturesEqual(t *testing.T, expected, actual []LayerFeature) bool {
	if !assert.Len(t, actual, len(expected)) {
		return false
	}

	expectedInterfaces := []interface{}{}
	for _, e := range expected {
		expectedInterfaces = append(expectedInterfaces, e)
	}

	actualInterfaces := []interface{}{}
	for _, a := range actual {
		actualInterfaces = append(actualInterfaces, a)
	}

	return AssertElementsEqual(t, expectedInterfaces, actualInterfaces)
}

// AssertNamespacesEqual asserts content in actual equals to content in
// expected regardless of ordering.
func AssertNamespacesEqual(t *testing.T, expected, actual []Namespace) bool {
	expectedInterfaces := []interface{}{}
	for _, e := range expected {
		expectedInterfaces = append(expectedInterfaces, e)
	}

	actualInterfaces := []interface{}{}
	for _, a := range actual {
		actualInterfaces = append(actualInterfaces, a)
	}

	return AssertElementsEqual(t, expectedInterfaces, actualInterfaces)
}

// AssertLayerNamespacesEqual asserts content in actual equals to content in
// expected regardless of ordering.
func AssertLayerNamespacesEqual(t *testing.T, expected, actual []LayerNamespace) bool {
	expectedInterfaces := []interface{}{}
	for _, e := range expected {
		expectedInterfaces = append(expectedInterfaces, e)
	}

	actualInterfaces := []interface{}{}
	for _, a := range actual {
		actualInterfaces = append(actualInterfaces, a)
	}

	return AssertElementsEqual(t, expectedInterfaces, actualInterfaces)
}

// AssertLayerEqual asserts actual layer equals to expected layer content wise.
func AssertLayerEqual(t *testing.T, expected, actual *Layer) bool {
	if expected == actual {
		return true
	}

	if expected == nil || actual == nil {
		return assert.Equal(t, expected, actual)
	}

	return assert.Equal(t, expected.Hash, actual.Hash) &&
		AssertDetectorsEqual(t, expected.By, actual.By) &&
		AssertLayerFeaturesEqual(t, expected.Features, actual.Features) &&
		AssertLayerNamespacesEqual(t, expected.Namespaces, actual.Namespaces)
}

// AssertIntStringMapEqual asserts two maps with integer as key and string as
// value are equal.
func AssertIntStringMapEqual(t *testing.T, expected, actual map[int]string) bool {
	checked := mapset.NewSet()
	for k, v := range expected {
		assert.Equal(t, v, actual[k])
		checked.Add(k)
	}

	for k := range actual {
		if !assert.True(t, checked.Contains(k)) {
			return false
		}
	}

	return true
}

// AssertVulnerabilityEqual asserts two vulnerabilities are equal.
func AssertVulnerabilityEqual(t *testing.T, expected, actual *Vulnerability) bool {
	return assert.Equal(t, expected.Name, actual.Name) &&
		assert.Equal(t, expected.Link, actual.Link) &&
		assert.Equal(t, expected.Description, actual.Description) &&
		assert.Equal(t, expected.Namespace, actual.Namespace) &&
		assert.Equal(t, expected.Severity, actual.Severity) &&
		AssertMetadataMapEqual(t, expected.Metadata, actual.Metadata)
}

func castMetadataMapToInterface(metadata MetadataMap) map[string]interface{} {
	content, err := json.Marshal(metadata)
	if err != nil {
		panic(err)
	}

	data := make(map[string]interface{})
	if err := json.Unmarshal(content, &data); err != nil {
		panic(err)
	}

	return data
}

// AssertMetadataMapEqual asserts two metadata maps are equal.
func AssertMetadataMapEqual(t *testing.T, expected, actual MetadataMap) bool {
	expectedMap := castMetadataMapToInterface(expected)
	actualMap := castMetadataMapToInterface(actual)
	checked := mapset.NewSet()
	for k, v := range expectedMap {
		if !assert.Equal(t, v, (actualMap)[k]) {
			return false
		}

		checked.Add(k)
	}

	for k := range actual {
		if !assert.True(t, checked.Contains(k)) {
			return false
		}
	}

	return true
}
