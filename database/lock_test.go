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
	"time"

	"github.com/coreos/clair/config"
	"github.com/stretchr/testify/assert"
)

func TestLock(t *testing.T) {
	Open(&config.DatabaseConfig{Type: "memstore"})
	defer Close()

	var l bool
	var et time.Time

	// Create a first lock
	l, _ = Lock("test1", time.Minute, "owner1")
	assert.True(t, l)
	// Try to lock the same lock with another owner
	l, _ = Lock("test1", time.Minute, "owner2")
	assert.False(t, l)
	// Renew the lock
	l, _ = Lock("test1", 2*time.Minute, "owner1")
	assert.True(t, l)
	// Unlock and then relock by someone else
	Unlock("test1", "owner1")
	l, et = Lock("test1", time.Minute, "owner2")
	assert.True(t, l)
	// LockInfo
	o, et2, err := LockInfo("test1")
	assert.Nil(t, err)
	assert.Equal(t, "owner2", o)
	assert.Equal(t, et.Second(), et2.Second())

	// Create a second lock which is actually already expired ...
	l, _ = Lock("test2", -time.Minute, "owner1")
	assert.True(t, l)
	// Take over the lock
	l, _ = Lock("test2", time.Minute, "owner2")
	assert.True(t, l)
}
