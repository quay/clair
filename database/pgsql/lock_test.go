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
	"time"

	"github.com/stretchr/testify/assert"
)

func TestLock(t *testing.T) {
	datastore, err := OpenForTest("InsertNamespace", false)
	if err != nil {
		t.Error(err)
		return
	}
	defer datastore.Close()

	var l bool
	var et time.Time

	// Create a first lock.
	l, _ = datastore.Lock("test1", "owner1", time.Minute, false)
	assert.True(t, l)

	// Try to lock the same lock with another owner.
	l, _ = datastore.Lock("test1", "owner2", time.Minute, true)
	assert.False(t, l)

	l, _ = datastore.Lock("test1", "owner2", time.Minute, false)
	assert.False(t, l)

	// Renew the lock.
	l, _ = datastore.Lock("test1", "owner1", 2*time.Minute, true)
	assert.True(t, l)

	// Unlock and then relock by someone else.
	datastore.Unlock("test1", "owner1")

	l, et = datastore.Lock("test1", "owner2", time.Minute, false)
	assert.True(t, l)

	// LockInfo
	o, et2, err := datastore.FindLock("test1")
	assert.Nil(t, err)
	assert.Equal(t, "owner2", o)
	assert.Equal(t, et.Second(), et2.Second())

	// Create a second lock which is actually already expired ...
	l, _ = datastore.Lock("test2", "owner1", -time.Minute, false)
	assert.True(t, l)

	// Take over the lock
	l, _ = datastore.Lock("test2", "owner2", time.Minute, false)
	assert.True(t, l)
}
