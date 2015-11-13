// Copyright 2015 quay-sec authors
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
	cerrors "github.com/coreos/quay-sec/utils/errors"
	"github.com/google/cayley"
	"github.com/google/cayley/graph"
	"github.com/google/cayley/graph/path"
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
	currentExpiration, err := toValue(cayley.StartPath(store, name).Has("locked_by", owner).Out("locked_until"))
	if err == nil && currentExpiration != "" {
		// Renew our lock
		if currentExpiration == untilString {
			return true, until
		}

		t := cayley.NewTransaction()
		t.RemoveQuad(cayley.Quad(name, "locked_until", currentExpiration, ""))
		t.AddQuad(cayley.Quad(name, "locked_until", untilString, ""))
		// It is not necessary to verify if the lock is ours again in the transaction
		// because if someone took it, the lock's current expiration probably changed and the transaction will fail
		return store.ApplyTransaction(t) == nil, until
	}

	t := cayley.NewTransaction()
	t.AddQuad(cayley.Quad(name, "locked", "locked", "")) // Necessary to make the transaction fails if the lock already exists (and has not been pruned)
	t.AddQuad(cayley.Quad(name, "locked_until", untilString, ""))
	t.AddQuad(cayley.Quad(name, "locked_by", owner, ""))

	glog.SetStderrThreshold("FATAL")
	success := store.ApplyTransaction(t) == nil
	glog.SetStderrThreshold("ERROR")

	return success, until
}

// Unlock unlocks a lock specified by its name if I own it
func Unlock(name, owner string) {
	pruneLocks()

	t := cayley.NewTransaction()
	it, _ := cayley.StartPath(store, name).Has("locked", "locked").Has("locked_by", owner).Save("locked_until", "locked_until").BuildIterator().Optimize()
	defer it.Close()

	for cayley.RawNext(it) {
		tags := make(map[string]graph.Value)
		it.TagResults(tags)

		t.RemoveQuad(cayley.Quad(name, "locked", "locked", ""))
		t.RemoveQuad(cayley.Quad(name, "locked_until", store.NameOf(tags["locked_until"]), ""))
		t.RemoveQuad(cayley.Quad(name, "locked_by", owner, ""))
	}

	store.ApplyTransaction(t)
}

// LockInfo returns the owner of a lock specified by its name and its
// expiration time
func LockInfo(name string) (string, time.Time, error) {
	it, _ := cayley.StartPath(store, name).Has("locked", "locked").Save("locked_until", "locked_until").Save("locked_by", "locked_by").BuildIterator().Optimize()
	defer it.Close()
	for cayley.RawNext(it) {
		tags := make(map[string]graph.Value)
		it.TagResults(tags)

		tt, _ := strconv.ParseInt(store.NameOf(tags["locked_until"]), 10, 64)
		return store.NameOf(tags["locked_by"]), time.Unix(tt, 0), nil
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
	tr := cayley.NewTransaction()
	it, _ := cayley.StartPath(store, "locked").In("locked").Save("locked_until", "locked_until").Save("locked_by", "locked_by").BuildIterator().Optimize()
	defer it.Close()
	for cayley.RawNext(it) {
		tags := make(map[string]graph.Value)
		it.TagResults(tags)

		n := store.NameOf(it.Result())
		t := store.NameOf(tags["locked_until"])
		o := store.NameOf(tags["locked_by"])
		tt, _ := strconv.ParseInt(t, 10, 64)

		if now.Unix() > tt {
			log.Debugf("Lock %s owned by %s has expired.", n, o)
			tr.RemoveQuad(cayley.Quad(n, "locked", "locked", ""))
			tr.RemoveQuad(cayley.Quad(n, "locked_until", t, ""))
			tr.RemoveQuad(cayley.Quad(n, "locked_by", o, ""))
		}
	}
	store.ApplyTransaction(tr)
}

// getLockedNodes returns every nodes that are currently locked
func getLockedNodes() *path.Path {
	return cayley.StartPath(store, "locked").In("locked")
}
