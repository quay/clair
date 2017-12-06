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
	"time"

	"github.com/stretchr/testify/assert"
)

func TestLock(t *testing.T) {
	datastore, tx := openSessionForTest(t, "Lock", true)
	defer datastore.Close()

	var l bool
	var et time.Time

	// Create a first lock.
	l, _, err := tx.Lock("test1", "owner1", time.Minute, false)
	assert.Nil(t, err)
	assert.True(t, l)
	tx = restartSession(t, datastore, tx, true)

	// lock again by itself, the previous lock is not expired yet.
	l, _, err = tx.Lock("test1", "owner1", time.Minute, false)
	assert.Nil(t, err)
	assert.False(t, l)
	tx = restartSession(t, datastore, tx, false)

	// Try to renew the same lock with another owner.
	l, _, err = tx.Lock("test1", "owner2", time.Minute, true)
	assert.Nil(t, err)
	assert.False(t, l)
	tx = restartSession(t, datastore, tx, false)

	l, _, err = tx.Lock("test1", "owner2", time.Minute, false)
	assert.Nil(t, err)
	assert.False(t, l)
	tx = restartSession(t, datastore, tx, false)

	// Renew the lock.
	l, _, err = tx.Lock("test1", "owner1", 2*time.Minute, true)
	assert.Nil(t, err)
	assert.True(t, l)
	tx = restartSession(t, datastore, tx, true)

	// Unlock and then relock by someone else.
	err = tx.Unlock("test1", "owner1")
	assert.Nil(t, err)
	tx = restartSession(t, datastore, tx, true)

	l, et, err = tx.Lock("test1", "owner2", time.Minute, false)
	assert.Nil(t, err)
	assert.True(t, l)
	tx = restartSession(t, datastore, tx, true)

	// LockInfo
	o, et2, ok, err := tx.FindLock("test1")
	assert.True(t, ok)
	assert.Nil(t, err)
	assert.Equal(t, "owner2", o)
	assert.Equal(t, et.Second(), et2.Second())
	tx = restartSession(t, datastore, tx, true)

	// Create a second lock which is actually already expired ...
	l, _, err = tx.Lock("test2", "owner1", -time.Minute, false)
	assert.Nil(t, err)
	assert.True(t, l)
	tx = restartSession(t, datastore, tx, true)

	// Take over the lock
	l, _, err = tx.Lock("test2", "owner2", time.Minute, false)
	assert.Nil(t, err)
	assert.True(t, l)
	tx = restartSession(t, datastore, tx, true)

	if !assert.Nil(t, tx.Rollback()) {
		t.FailNow()
	}
}
