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
	"database/sql"
	"time"

	"github.com/guregu/null/zero"
	"github.com/pborman/uuid"
	log "github.com/sirupsen/logrus"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/pkg/commonerr"
)

// do it in tx so we won't insert/update a vuln without notification and vice-versa.
// name and created doesn't matter.
func createNotification(tx *sql.Tx, oldVulnerabilityID, newVulnerabilityID int) error {
	defer observeQueryTime("createNotification", "all", time.Now())

	// Insert Notification.
	oldVulnerabilityNullableID := sql.NullInt64{Int64: int64(oldVulnerabilityID), Valid: oldVulnerabilityID != 0}
	newVulnerabilityNullableID := sql.NullInt64{Int64: int64(newVulnerabilityID), Valid: newVulnerabilityID != 0}
	_, err := tx.Exec(insertNotification, uuid.New(), oldVulnerabilityNullableID, newVulnerabilityNullableID)
	if err != nil {
		tx.Rollback()
		return handleError("insertNotification", err)
	}

	return nil
}

// Get one available notification name (!locked && !deleted && (!notified || notified_but_timed-out)).
// Does not fill new/old vuln.
func (pgSQL *pgSQL) GetAvailableNotification(renotifyInterval time.Duration) (database.VulnerabilityNotification, error) {
	defer observeQueryTime("GetAvailableNotification", "all", time.Now())

	before := time.Now().Add(-renotifyInterval)
	row := pgSQL.QueryRow(searchNotificationAvailable, before)
	notification, err := pgSQL.scanNotification(row, false)

	return notification, handleError("searchNotificationAvailable", err)
}

func (pgSQL *pgSQL) GetNotification(name string, limit int, page database.VulnerabilityNotificationPageNumber) (database.VulnerabilityNotification, database.VulnerabilityNotificationPageNumber, error) {
	defer observeQueryTime("GetNotification", "all", time.Now())

	// Get Notification.
	notification, err := pgSQL.scanNotification(pgSQL.QueryRow(searchNotification, name), true)
	if err != nil {
		return notification, page, handleError("searchNotification", err)
	}

	// Load vulnerabilities' LayersIntroducingVulnerability.
	page.OldVulnerability, err = pgSQL.loadLayerIntroducingVulnerability(
		notification.OldVulnerability,
		limit,
		page.OldVulnerability,
	)

	if err != nil {
		return notification, page, err
	}

	page.NewVulnerability, err = pgSQL.loadLayerIntroducingVulnerability(
		notification.NewVulnerability,
		limit,
		page.NewVulnerability,
	)

	if err != nil {
		return notification, page, err
	}

	return notification, page, nil
}

func (pgSQL *pgSQL) scanNotification(row *sql.Row, hasVulns bool) (database.VulnerabilityNotification, error) {
	var notification database.VulnerabilityNotification
	var created zero.Time
	var notified zero.Time
	var deleted zero.Time
	var oldVulnerabilityNullableID sql.NullInt64
	var newVulnerabilityNullableID sql.NullInt64

	// Scan notification.
	if hasVulns {
		err := row.Scan(
			&notification.ID,
			&notification.Name,
			&created,
			&notified,
			&deleted,
			&oldVulnerabilityNullableID,
			&newVulnerabilityNullableID,
		)

		if err != nil {
			return notification, err
		}
	} else {
		err := row.Scan(&notification.ID, &notification.Name, &created, &notified, &deleted)

		if err != nil {
			return notification, err
		}
	}

	notification.Created = created.Time
	notification.Notified = notified.Time
	notification.Deleted = deleted.Time

	if hasVulns {
		if oldVulnerabilityNullableID.Valid {
			vulnerability, err := pgSQL.findVulnerabilityByIDWithDeleted(int(oldVulnerabilityNullableID.Int64))
			if err != nil {
				return notification, err
			}

			notification.OldVulnerability = &vulnerability
		}

		if newVulnerabilityNullableID.Valid {
			vulnerability, err := pgSQL.findVulnerabilityByIDWithDeleted(int(newVulnerabilityNullableID.Int64))
			if err != nil {
				return notification, err
			}

			notification.NewVulnerability = &vulnerability
		}
	}

	return notification, nil
}

// Fills Vulnerability.LayersIntroducingVulnerability.
// limit -1: won't do anything
// limit 0: will just get the startID of the second page
func (pgSQL *pgSQL) loadLayerIntroducingVulnerability(vulnerability *database.Vulnerability, limit, startID int) (int, error) {
	tf := time.Now()

	if vulnerability == nil {
		return -1, nil
	}

	// A startID equals to -1 means that we reached the end already.
	if startID == -1 || limit == -1 {
		return -1, nil
	}

	// Create a transaction to disable hash joins as our experience shows that
	// PostgreSQL plans in certain cases a sequential scan and a hash on
	// Layer_diff_FeatureVersion for the condition `ldfv.layer_id >= $2 AND
	// ldfv.modification = 'add'` before realizing a hash inner join with
	// Vulnerability_Affects_FeatureVersion. By disabling explictly hash joins,
	// we force PostgreSQL to perform a bitmap index scan with
	// `ldfv.featureversion_id = fv.id` on Layer_diff_FeatureVersion, followed by
	// a bitmap heap scan on `ldfv.layer_id >= $2 AND ldfv.modification = 'add'`,
	// thus avoiding a sequential scan on the biggest database table and
	// allowing a small nested loop join instead.
	tx, err := pgSQL.Begin()
	if err != nil {
		return -1, handleError("searchNotificationLayerIntroducingVulnerability.Begin()", err)
	}
	defer tx.Commit()

	_, err = tx.Exec(disableHashJoin)
	if err != nil {
		log.WithError(err).Warning("searchNotificationLayerIntroducingVulnerability: could not disable hash join")
	}

	// We do `defer observeQueryTime` here because we don't want to observe invalid calls.
	defer observeQueryTime("loadLayerIntroducingVulnerability", "all", tf)

	// Query with limit + 1, the last item will be used to know the next starting ID.
	rows, err := tx.Query(searchNotificationLayerIntroducingVulnerability,
		vulnerability.ID, startID, limit+1)
	if err != nil {
		return 0, handleError("searchNotificationLayerIntroducingVulnerability", err)
	}
	defer rows.Close()

	var layers []database.Layer
	for rows.Next() {
		var layer database.Layer

		if err := rows.Scan(&layer.ID, &layer.Name); err != nil {
			return -1, handleError("searchNotificationLayerIntroducingVulnerability.Scan()", err)
		}

		layers = append(layers, layer)
	}
	if err = rows.Err(); err != nil {
		return -1, handleError("searchNotificationLayerIntroducingVulnerability.Rows()", err)
	}

	size := limit
	if len(layers) < limit {
		size = len(layers)
	}
	vulnerability.LayersIntroducingVulnerability = layers[:size]

	nextID := -1
	if len(layers) > limit {
		nextID = layers[limit].ID
	}

	return nextID, nil
}

func (pgSQL *pgSQL) SetNotificationNotified(name string) error {
	defer observeQueryTime("SetNotificationNotified", "all", time.Now())

	if _, err := pgSQL.Exec(updatedNotificationNotified, name); err != nil {
		return handleError("updatedNotificationNotified", err)
	}
	return nil
}

func (pgSQL *pgSQL) DeleteNotification(name string) error {
	defer observeQueryTime("DeleteNotification", "all", time.Now())

	result, err := pgSQL.Exec(removeNotification, name)
	if err != nil {
		return handleError("removeNotification", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return handleError("removeNotification.RowsAffected()", err)
	}

	if affected <= 0 {
		return commonerr.ErrNotFound
	}

	return nil
}
