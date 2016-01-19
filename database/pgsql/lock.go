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
	"database/sql"
	"time"

	cerrors "github.com/coreos/clair/utils/errors"
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

	// Prune locks.
	pgSQL.pruneLocks()

	// Compute expiration.
	until := time.Now().Add(duration)

	if renew {
		// Renew lock.
		r, err := pgSQL.Exec(getQuery("u_lock"), name, owner, until)
		if err != nil {
			handleError("u_lock", err)
			return false, until
		}
		if n, _ := r.RowsAffected(); n > 0 {
			// Updated successfully.
			return true, until
		}
	}

	// Lock.
	_, err := pgSQL.Exec(getQuery("i_lock"), name, owner, until)
	if err != nil {
		if !isErrUniqueViolation(err) {
			handleError("i_lock", err)
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

	pgSQL.Exec(getQuery("r_lock"), name, owner)
}

// FindLock returns the owner of a lock specified by its name and its
// expiration time.
func (pgSQL *pgSQL) FindLock(name string) (string, time.Time, error) {
	if name == "" {
		log.Warning("could not find an invalid lock")
		return "", time.Time{}, cerrors.NewBadRequestError("could not find an invalid lock")
	}

	var owner string
	var until time.Time
	err := pgSQL.QueryRow(getQuery("f_lock"), name).Scan(&owner, &until)

	if err == sql.ErrNoRows {
		return owner, until, cerrors.ErrNotFound
	}
	if err != nil {
		return owner, until, handleError("f_lock", err)
	}

	return owner, until, nil
}

// pruneLocks removes every expired locks from the database
func (pgSQL *pgSQL) pruneLocks() {
	if _, err := pgSQL.Exec(getQuery("r_lock_expired")); err != nil {
		handleError("r_lock_expired", err)
	}
}
