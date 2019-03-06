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
	"database/sql"
	"time"

	"github.com/coreos/clair/database/pgsql/monitoring"
	"github.com/coreos/clair/database/pgsql/util"
	log "github.com/sirupsen/logrus"
)

const (
	searchLock        = `SELECT until FROM Lock WHERE name = $1`
	updateLock        = `UPDATE Lock SET until = $3 WHERE name = $1 AND owner = $2`
	removeLock        = `DELETE FROM Lock WHERE name = $1 AND owner = $2`
	removeLockExpired = `DELETE FROM LOCK WHERE until < $1`

	soiLock = `
	WITH new_lock AS (
		INSERT INTO lock (name, owner, until) 
		SELECT CAST ($1 AS TEXT), CAST ($2 AS TEXT), CAST ($3 AS TIMESTAMP)
		WHERE NOT EXISTS (SELECT id FROM lock WHERE name = $1)
		RETURNING owner, until
	)
	SELECT * FROM new_lock
	UNION
	SELECT owner, until FROM lock WHERE name = $1`
)

func AcquireLock(tx *sql.Tx, lockName, whoami string, desiredDuration time.Duration) (bool, time.Time, error) {
	if lockName == "" || whoami == "" || desiredDuration == 0 {
		panic("invalid lock parameters")
	}

	if err := PruneLocks(tx); err != nil {
		return false, time.Time{}, err
	}

	var (
		desiredLockedUntil = time.Now().UTC().Add(desiredDuration)

		lockedUntil time.Time
		lockOwner   string
	)

	defer monitoring.ObserveQueryTime("Lock", "soiLock", time.Now())
	err := tx.QueryRow(soiLock, lockName, whoami, desiredLockedUntil).Scan(&lockOwner, &lockedUntil)
	return lockOwner == whoami, lockedUntil, util.HandleError("AcquireLock", err)
}

func ExtendLock(tx *sql.Tx, lockName, whoami string, desiredDuration time.Duration) (bool, time.Time, error) {
	if lockName == "" || whoami == "" || desiredDuration == 0 {
		panic("invalid lock parameters")
	}

	desiredLockedUntil := time.Now().Add(desiredDuration)

	defer monitoring.ObserveQueryTime("Lock", "update", time.Now())
	result, err := tx.Exec(updateLock, lockName, whoami, desiredLockedUntil)
	if err != nil {
		return false, time.Time{}, util.HandleError("updateLock", err)
	}

	if numRows, err := result.RowsAffected(); err == nil {
		// This is the only happy path.
		return numRows > 0, desiredLockedUntil, nil
	}

	return false, time.Time{}, util.HandleError("updateLock", err)
}

func ReleaseLock(tx *sql.Tx, name, owner string) error {
	if name == "" || owner == "" {
		panic("invalid lock parameters")
	}

	defer monitoring.ObserveQueryTime("Unlock", "all", time.Now())
	_, err := tx.Exec(removeLock, name, owner)
	return err
}

// pruneLocks removes every expired locks from the database
func PruneLocks(tx *sql.Tx) error {
	defer monitoring.ObserveQueryTime("pruneLocks", "all", time.Now())

	if r, err := tx.Exec(removeLockExpired, time.Now().UTC()); err != nil {
		return util.HandleError("removeLockExpired", err)
	} else if affected, err := r.RowsAffected(); err != nil {
		return util.HandleError("removeLockExpired", err)
	} else {
		log.Debugf("Pruned %d Locks", affected)
	}

	return nil
}
