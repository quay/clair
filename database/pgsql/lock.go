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
	"errors"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/coreos/clair/pkg/commonerr"
)

var (
	errLockNotFound = errors.New("lock is not in database")
)

// Lock tries to set a temporary lock in the database.
//
// Lock does not block, instead, it returns true and its expiration time
// is the lock has been successfully acquired or false otherwise.
func (tx *pgSession) Lock(name string, owner string, duration time.Duration, renew bool) (bool, time.Time, error) {
	if name == "" || owner == "" || duration == 0 {
		log.Warning("could not create an invalid lock")
		return false, time.Time{}, commonerr.NewBadRequestError("Invalid Lock Parameters")
	}

	until := time.Now().Add(duration)
	if renew {
		defer observeQueryTime("Lock", "update", time.Now())
		// Renew lock.
		r, err := tx.Exec(updateLock, name, owner, until)
		if err != nil {
			return false, until, handleError("updateLock", err)
		}

		if n, err := r.RowsAffected(); err == nil {
			return n > 0, until, nil
		}
		return false, until, handleError("updateLock", err)
	} else if err := tx.pruneLocks(); err != nil {
		return false, until, err
	}

	// Lock.
	defer observeQueryTime("Lock", "soiLock", time.Now())
	_, err := tx.Exec(soiLock, name, owner, until)
	if err != nil {
		if isErrUniqueViolation(err) {
			return false, until, nil
		}
		return false, until, handleError("insertLock", err)
	}
	return true, until, nil
}

// Unlock unlocks a lock specified by its name if I own it
func (tx *pgSession) Unlock(name, owner string) error {
	if name == "" || owner == "" {
		return commonerr.NewBadRequestError("Invalid Lock Parameters")
	}

	defer observeQueryTime("Unlock", "all", time.Now())

	_, err := tx.Exec(removeLock, name, owner)
	return err
}

// FindLock returns the owner of a lock specified by its name and its
// expiration time.
func (tx *pgSession) FindLock(name string) (string, time.Time, bool, error) {
	if name == "" {
		return "", time.Time{}, false, commonerr.NewBadRequestError("could not find an invalid lock")
	}

	defer observeQueryTime("FindLock", "all", time.Now())

	var owner string
	var until time.Time
	err := tx.QueryRow(searchLock, name).Scan(&owner, &until)
	if err != nil {
		return owner, until, false, handleError("searchLock", err)
	}

	return owner, until, true, nil
}

// pruneLocks removes every expired locks from the database
func (tx *pgSession) pruneLocks() error {
	defer observeQueryTime("pruneLocks", "all", time.Now())

	if r, err := tx.Exec(removeLockExpired); err != nil {
		return handleError("removeLockExpired", err)
	} else if affected, err := r.RowsAffected(); err != nil {
		return handleError("removeLockExpired", err)
	} else {
		log.Debugf("Pruned %d Locks", affected)
	}

	return nil
}
