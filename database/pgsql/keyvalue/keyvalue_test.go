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

package keyvalue

import (
	"testing"

	"github.com/coreos/clair/database/pgsql/testutil"
	"github.com/stretchr/testify/assert"
)

func TestKeyValue(t *testing.T) {
	tx, cleanup := testutil.CreateTestTxWithFixtures(t, "KeyValue")
	defer cleanup()

	// Get non-existing key/value
	f, ok, err := FindKeyValue(tx, "test")
	assert.Nil(t, err)
	assert.False(t, ok)

	// Try to insert invalid key/value.
	assert.Error(t, UpdateKeyValue(tx, "test", ""))
	assert.Error(t, UpdateKeyValue(tx, "", "test"))
	assert.Error(t, UpdateKeyValue(tx, "", ""))

	// Insert and verify.
	assert.Nil(t, UpdateKeyValue(tx, "test", "test1"))
	f, ok, err = FindKeyValue(tx, "test")
	assert.Nil(t, err)
	assert.True(t, ok)
	assert.Equal(t, "test1", f)

	// Update and verify.
	assert.Nil(t, UpdateKeyValue(tx, "test", "test2"))
	f, ok, err = FindKeyValue(tx, "test")
	assert.Nil(t, err)
	assert.True(t, ok)
	assert.Equal(t, "test2", f)
}
