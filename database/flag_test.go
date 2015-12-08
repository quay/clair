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
	"github.com/stretchr/testify/assert"
)

func TestFlag(t *testing.T) {
	Open(&config.DatabaseConfig{Type: "memstore"})
	defer Close()

	// Get non existing flag
	f, err := GetFlagValue("test")
	assert.Nil(t, err, "GetFlagValue should have worked")
	assert.Empty(t, "", f, "Getting a non-existing flag should return an empty string")

	// Try to insert invalid flags
	assert.Error(t, UpdateFlag("test", ""), "It should not accept a flag with an empty name or value")
	assert.Error(t, UpdateFlag("", "test"), "It should not accept a flag with an empty name or value")
	assert.Error(t, UpdateFlag("", ""), "It should not accept a flag with an empty name or value")

	// Insert a flag and verify its value
	assert.Nil(t, UpdateFlag("test", "test1"))
	f, err = GetFlagValue("test")
	assert.Nil(t, err, "GetFlagValue should have worked")
	assert.Equal(t, "test1", f, "GetFlagValue did not return the expected value")

	// Update a flag and verify its value
	assert.Nil(t, UpdateFlag("test", "test2"))
	f, err = GetFlagValue("test")
	assert.Nil(t, err, "GetFlagValue should have worked")
	assert.Equal(t, "test2", f, "GetFlagValue did not return the expected value")
}
