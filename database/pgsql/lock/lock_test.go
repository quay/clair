// Copyright 2019 clair authors
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

package lock

import (
	"testing"
	"time"

	"github.com/coreos/clair/database/pgsql/testutil"
	"github.com/stretchr/testify/require"
)

func TestAcquireLockReturnsExistingLockDuration(t *testing.T) {
	tx, cleanup := testutil.CreateTestTxWithFixtures(t, "Lock")
	defer cleanup()

	acquired, originalExpiration, err := AcquireLock(tx, "test1", "owner1", time.Minute)
	require.Nil(t, err)
	require.True(t, acquired)

	acquired2, expiration, err := AcquireLock(tx, "test1", "owner2", time.Hour)
	require.Nil(t, err)
	require.False(t, acquired2)
	require.Equal(t, expiration, originalExpiration)
}

func TestLock(t *testing.T) {
	db, cleanup := testutil.CreateTestDBWithFixture(t, "Lock")
	defer cleanup()

	tx, err := db.Begin()
	if err != nil {
		panic(err)
	}

	// Create a first lock.
	l, _, err := AcquireLock(tx, "test1", "owner1", time.Minute)
	require.Nil(t, err)
	require.True(t, l)
	tx = testutil.RestartTransaction(db, tx, true)

	// lock again by itself, the previous lock is not expired yet.
	l, _, err = AcquireLock(tx, "test1", "owner1", time.Minute)
	require.Nil(t, err)
	require.True(t, l)
	tx = testutil.RestartTransaction(db, tx, false)

	// Try to renew the same lock with another owner.
	l, _, err = ExtendLock(tx, "test1", "owner2", time.Minute)
	require.Nil(t, err)
	require.False(t, l)
	tx = testutil.RestartTransaction(db, tx, false)

	l, _, err = AcquireLock(tx, "test1", "owner2", time.Minute)
	require.Nil(t, err)
	require.False(t, l)
	tx = testutil.RestartTransaction(db, tx, false)

	// Renew the lock.
	l, _, err = ExtendLock(tx, "test1", "owner1", 2*time.Minute)
	require.Nil(t, err)
	require.True(t, l)
	tx = testutil.RestartTransaction(db, tx, true)

	// Unlock and then relock by someone else.
	err = ReleaseLock(tx, "test1", "owner1")
	require.Nil(t, err)
	tx = testutil.RestartTransaction(db, tx, true)

	l, _, err = AcquireLock(tx, "test1", "owner2", time.Minute)
	require.Nil(t, err)
	require.True(t, l)
	tx = testutil.RestartTransaction(db, tx, true)

	// Create a second lock which is actually already expired ...
	l, _, err = AcquireLock(tx, "test2", "owner1", -time.Minute)
	require.Nil(t, err)
	require.True(t, l)
	tx = testutil.RestartTransaction(db, tx, true)

	// Take over the lock
	l, _, err = AcquireLock(tx, "test2", "owner2", time.Minute)
	require.Nil(t, err)
	require.True(t, l)
	tx = testutil.RestartTransaction(db, tx, true)

	require.Nil(t, tx.Rollback())
}
