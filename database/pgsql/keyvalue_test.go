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

package pgsql

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestKeyValue(t *testing.T) {
	datastore, tx := openSessionForTest(t, "KeyValue", true)
	defer closeTest(t, datastore, tx)

	// Get non-existing key/value
	f, ok, err := tx.FindKeyValue("test")
	assert.Nil(t, err)
	assert.False(t, ok)

	// Try to insert invalid key/value.
	assert.Error(t, tx.UpdateKeyValue("test", ""))
	assert.Error(t, tx.UpdateKeyValue("", "test"))
	assert.Error(t, tx.UpdateKeyValue("", ""))

	// Insert and verify.
	assert.Nil(t, tx.UpdateKeyValue("test", "test1"))
	f, ok, err = tx.FindKeyValue("test")
	assert.Nil(t, err)
	assert.True(t, ok)
	assert.Equal(t, "test1", f)

	// Update and verify.
	assert.Nil(t, tx.UpdateKeyValue("test", "test2"))
	f, ok, err = tx.FindKeyValue("test")
	assert.Nil(t, err)
	assert.True(t, ok)
	assert.Equal(t, "test2", f)
}
