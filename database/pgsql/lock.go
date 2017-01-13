// Copyright 2017 clair authors
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
	"time"

	"github.com/coreos/clair/pkg/commonerr"
)

// Lock tries to set a temporary lock in the database.
//
// Lock does not block, instead, it returns true and its expiration time
// is the lock has been successfully acquired or false otherwise
func (pgSQL *pgSQL) Lock(name string, owner string, duration time.Duration, renew bool) (bool, time.Time) {
	if name == "" || owner == "" || duration == 0 {
		log.Warning("could not create an invalid lock")
		return false, time.Time{}
	}

	defer observeQueryTime("Lock", "all", time.Now())

	// Compute expiration.
	until := time.Now().Add(duration)

	if renew {
		// Renew lock.
		r, err := pgSQL.Exec(updateLock, name, owner, until)
		if err != nil {
			handleError("updateLock", err)
			return false, until
		}
		if n, _ := r.RowsAffected(); n > 0 {
			// Updated successfully.
			return true, until
		}
	} else {
		// Prune locks.
		pgSQL.pruneLocks()
	}

	// Lock.
	_, err := pgSQL.Exec(insertLock, name, owner, until)
	if err != nil {
		if !isErrUniqueViolation(err) {
			handleError("insertLock", err)
		}
		return false, until
	}

	return true, until
}

// Unlock unlocks a lock specified by its name if I own it
func (pgSQL *pgSQL) Unlock(name, owner string) {
	if name == "" || owner == "" {
		log.Warning("could not delete an invalid lock")
		return
	}

	defer observeQueryTime("Unlock", "all", time.Now())

	pgSQL.Exec(removeLock, name, owner)
}

// FindLock returns the owner of a lock specified by its name and its
// expiration time.
func (pgSQL *pgSQL) FindLock(name string) (string, time.Time, error) {
	if name == "" {
		log.Warning("could not find an invalid lock")
		return "", time.Time{}, commonerr.NewBadRequestError("could not find an invalid lock")
	}

	defer observeQueryTime("FindLock", "all", time.Now())

	var owner string
	var until time.Time
	err := pgSQL.QueryRow(searchLock, name).Scan(&owner, &until)
	if err != nil {
		return owner, until, handleError("searchLock", err)
	}

	return owner, until, nil
}

// pruneLocks removes every expired locks from the database
func (pgSQL *pgSQL) pruneLocks() {
	defer observeQueryTime("pruneLocks", "all", time.Now())

	if _, err := pgSQL.Exec(removeLockExpired); err != nil {
		handleError("removeLockExpired", err)
	}
}
