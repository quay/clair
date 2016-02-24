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

package pgsql

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestKeyValue(t *testing.T) {
	datastore, err := OpenForTest("KeyValue", false)
	if err != nil {
		t.Error(err)
		return
	}
	defer datastore.Close()

	// Get non-existing key/value
	f, err := datastore.GetKeyValue("test")
	assert.Nil(t, err)
	assert.Empty(t, "", f)

	// Try to insert invalid key/value.
	assert.Error(t, datastore.InsertKeyValue("test", ""))
	assert.Error(t, datastore.InsertKeyValue("", "test"))
	assert.Error(t, datastore.InsertKeyValue("", ""))

	// Insert and verify.
	assert.Nil(t, datastore.InsertKeyValue("test", "test1"))
	f, err = datastore.GetKeyValue("test")
	assert.Nil(t, err)
	assert.Equal(t, "test1", f)

	// Update and verify.
	assert.Nil(t, datastore.InsertKeyValue("test", "test2"))
	f, err = datastore.GetKeyValue("test")
	assert.Nil(t, err)
	assert.Equal(t, "test2", f)
}
