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

package database

import (
	"testing"

	"github.com/coreos/clair/config"
	"github.com/google/cayley"
	"github.com/stretchr/testify/assert"
)

func TestHealthcheck(t *testing.T) {
	Open(&config.DatabaseConfig{Type: "memstore"})
	defer Close()

	b := Healthcheck()
	assert.True(t, b.IsHealthy, "Healthcheck failed")
}

func TestToValue(t *testing.T) {
	Open(&config.DatabaseConfig{Type: "memstore"})
	defer Close()

	// toValue()
	v, err := toValue(cayley.StartPath(store, "tests").Out("are"))
	assert.Nil(t, err, "toValue should work even if the requested path leads to nothing")
	assert.Equal(t, "", v, "toValue should return an empty string if the requested path leads to nothing")

	store.AddQuad(cayley.Triple("tests", "are", "awesome"))
	v, err = toValue(cayley.StartPath(store, "tests").Out("are"))
	assert.Nil(t, err, "toValue should have worked")
	assert.Equal(t, "awesome", v, "toValue did not return the expected value")

	store.AddQuad(cayley.Triple("tests", "are", "running"))
	v, err = toValue(cayley.StartPath(store, "tests").Out("are"))
	assert.NotNil(t, err, "toValue should return an error and an empty string if the path leads to multiple values")
	assert.Equal(t, "", v, "toValue should return an error and an empty string if the path leads to multiple values")

	// toValues()
	vs, err := toValues(cayley.StartPath(store, "CoreOS").Out(fieldIs))
	assert.Nil(t, err, "toValues should work even if the requested path leads to nothing")
	assert.Len(t, vs, 0, "toValue should return an empty array if the requested path leads to nothing")
	words := []string{"powerful", "lightweight"}
	for i, word := range words {
		store.AddQuad(cayley.Triple("CoreOS", fieldIs, word))
		v, err := toValues(cayley.StartPath(store, "CoreOS").Out(fieldIs))
		assert.Nil(t, err, "toValues should have worked")
		assert.Len(t, v, i+1, "toValues did not return the right amount of values")
		for _, e := range words[:i+1] {
			assert.Contains(t, v, e, "toValues did not return the values we expected")
		}
	}

	// toValue(s)() and empty values
	store.AddQuad(cayley.Triple("bob", "likes", ""))
	v, err = toValue(cayley.StartPath(store, "bob").Out("likes"))
	assert.Nil(t, err, "toValue should work even if the requested path leads to nothing")
	assert.Equal(t, "", v, "toValue should return an empty string if the requested path leads to nothing")

	store.AddQuad(cayley.Triple("bob", "likes", "running"))
	v, err = toValue(cayley.StartPath(store, "bob").Out("likes"))
	assert.NotNil(t, err, "toValue should return an error and an empty string if the path leads to multiple values")
	assert.Equal(t, "", v, "toValue should return an error and an empty string if the path leads to multiple values")

	store.AddQuad(cayley.Triple("bob", "likes", "swimming"))
	va, err := toValues(cayley.StartPath(store, "bob").Out("likes"))
	assert.Nil(t, err, "toValues should have worked")
	if assert.Len(t, va, 3, "toValues should have returned 2 values") {
		assert.Contains(t, va, "running")
		assert.Contains(t, va, "swimming")
		assert.Contains(t, va, "")
	}
}
