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
	"strconv"
	"time"

	"github.com/barakmich/glog"
	cerrors "github.com/coreos/clair/utils/errors"
	"github.com/google/cayley"
	"github.com/google/cayley/graph"
	"github.com/google/cayley/graph/path"
)

const (
	fieldLockLocked      = "locked"
	fieldLockLockedValue = "locked"
	fieldLockLockedBy    = "locked_by"
	fieldLockLockedUntil = "locked_until"
)

// Lock tries to set a temporary lock in the database.
// If a lock already exists with the given name/owner, then the lock is renewed
//
// Lock does not block, instead, it returns true and its expiration time
// is the lock has been successfully acquired or false otherwise
func Lock(name string, duration time.Duration, owner string) (bool, time.Time) {
	pruneLocks()

	until := time.Now().Add(duration)
	untilString := strconv.FormatInt(until.Unix(), 10)

	// Try to get the expiration time of a lock with the same name/owner
	currentExpiration, err := toValue(cayley.StartPath(store, name).Has(fieldLockLockedBy, owner).Out(fieldLockLockedUntil))
	if err == nil && currentExpiration != "" {
		// Renew our lock
		if currentExpiration == untilString {
			return true, until
		}

		t := cayley.NewTransaction()
		t.RemoveQuad(cayley.Triple(name, fieldLockLockedUntil, currentExpiration))
		t.AddQuad(cayley.Triple(name, fieldLockLockedUntil, untilString))
		// It is not necessary to verify if the lock is ours again in the transaction
		// because if someone took it, the lock's current expiration probably changed and the transaction will fail
		return store.ApplyTransaction(t) == nil, until
	}

	t := cayley.NewTransaction()
	t.AddQuad(cayley.Triple(name, fieldLockLocked, fieldLockLockedValue)) // Necessary to make the transaction fails if the lock already exists (and has not been pruned)
	t.AddQuad(cayley.Triple(name, fieldLockLockedUntil, untilString))
	t.AddQuad(cayley.Triple(name, fieldLockLockedBy, owner))

	glog.SetStderrThreshold("FATAL")
	success := store.ApplyTransaction(t) == nil
	glog.SetStderrThreshold("ERROR")

	return success, until
}

// Unlock unlocks a lock specified by its name if I own it
func Unlock(name, owner string) {
	unlocked := 0
	it, _ := cayley.StartPath(store, name).Has(fieldLockLocked, fieldLockLockedValue).Has(fieldLockLockedBy, owner).Save(fieldLockLockedUntil, fieldLockLockedUntil).BuildIterator().Optimize()
	defer it.Close()
	for cayley.RawNext(it) {
		tags := make(map[string]graph.Value)
		it.TagResults(tags)

		t := cayley.NewTransaction()
		t.RemoveQuad(cayley.Triple(name, fieldLockLocked, fieldLockLockedValue))
		t.RemoveQuad(cayley.Triple(name, fieldLockLockedUntil, store.NameOf(tags[fieldLockLockedUntil])))
		t.RemoveQuad(cayley.Triple(name, fieldLockLockedBy, owner))
		err := store.ApplyTransaction(t)
		if err != nil {
			log.Errorf("failed transaction (Unlock): %s", err)
		}

		unlocked++
	}
	if it.Err() != nil {
		log.Errorf("failed query in Unlock: %s", it.Err())
	}
	if unlocked > 1 {
		// We should never see this, it would mean that our database doesn't ensure quad uniqueness
		// and that the entire lock system is jeopardized.
		log.Errorf("found inconsistency in Unlock: matched %d times a locked named: %s", unlocked, name)
	}
}

// LockInfo returns the owner of a lock specified by its name and its
// expiration time
func LockInfo(name string) (string, time.Time, error) {
	it, _ := cayley.StartPath(store, name).Has(fieldLockLocked, fieldLockLockedValue).Save(fieldLockLockedUntil, fieldLockLockedUntil).Save(fieldLockLockedBy, fieldLockLockedBy).BuildIterator().Optimize()
	defer it.Close()
	for cayley.RawNext(it) {
		tags := make(map[string]graph.Value)
		it.TagResults(tags)

		tt, _ := strconv.ParseInt(store.NameOf(tags[fieldLockLockedUntil]), 10, 64)
		return store.NameOf(tags[fieldLockLockedBy]), time.Unix(tt, 0), nil
	}
	if it.Err() != nil {
		log.Errorf("failed query in LockInfo: %s", it.Err())
		return "", time.Time{}, ErrBackendException
	}

	return "", time.Time{}, cerrors.ErrNotFound
}

// pruneLocks removes every expired locks from the database
func pruneLocks() {
	now := time.Now()

	// Delete every expired locks
	it, _ := cayley.StartPath(store, "locked").In("locked").Save(fieldLockLockedUntil, fieldLockLockedUntil).Save(fieldLockLockedBy, fieldLockLockedBy).BuildIterator().Optimize()
	defer it.Close()
	for cayley.RawNext(it) {
		tags := make(map[string]graph.Value)
		it.TagResults(tags)

		n := store.NameOf(it.Result())
		t := store.NameOf(tags[fieldLockLockedUntil])
		o := store.NameOf(tags[fieldLockLockedBy])
		tt, _ := strconv.ParseInt(t, 10, 64)

		if now.Unix() > tt {
			log.Debugf("lock %s owned by %s has expired.", n, o)

			tr := cayley.NewTransaction()
			tr.RemoveQuad(cayley.Triple(n, fieldLockLocked, fieldLockLockedValue))
			tr.RemoveQuad(cayley.Triple(n, fieldLockLockedUntil, t))
			tr.RemoveQuad(cayley.Triple(n, fieldLockLockedBy, o))
			err := store.ApplyTransaction(tr)
			if err != nil {
				log.Errorf("failed transaction (pruneLocks): %s", err)
				continue
			}
			log.Debugf("lock %s has been successfully pruned.", n)
		}
	}
	if it.Err() != nil {
		log.Errorf("failed query in Unlock: %s", it.Err())
	}
}

// getLockedNodes returns every nodes that are currently locked
func getLockedNodes() *path.Path {
	return cayley.StartPath(store, "locked").In("locked")
}
