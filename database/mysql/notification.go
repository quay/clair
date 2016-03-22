package mysql

import (
	"database/sql"
	"time"

	"github.com/coreos/clair/database"
	cerrors "github.com/coreos/clair/utils/errors"
	"github.com/guregu/null/zero"
	"github.com/pborman/uuid"
)

// do it in tx so we won't insert/update a vuln without notification and vice-versa.
// name and created doesn't matter.
func createNotification(tx *sql.Tx, oldVulnerabilityID, newVulnerabilityID int) error {
	defer database.ObserveQueryTime("createNotification", "all", time.Now())

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
func (mySQL *mySQL) GetAvailableNotification(renotifyInterval time.Duration) (database.VulnerabilityNotification, error) {
	defer database.ObserveQueryTime("GetAvailableNotification", "all", time.Now())

	before := time.Now().Add(-renotifyInterval)
	row := mySQL.QueryRow(searchNotificationAvailable, before)
	notification, err := mySQL.scanNotification(row, false)

	return notification, handleError("searchNotificationAvailable", err)
}

func (mySQL *mySQL) GetNotification(name string, limit int, page database.VulnerabilityNotificationPageNumber) (database.VulnerabilityNotification, database.VulnerabilityNotificationPageNumber, error) {
	defer database.ObserveQueryTime("GetNotification", "all", time.Now())

	// Get Notification.
	notification, err := mySQL.scanNotification(mySQL.QueryRow(searchNotification, name), true)
	if err != nil {
		return notification, page, handleError("searchNotification", err)
	}

	// Load vulnerabilities' LayersIntroducingVulnerability.
	page.OldVulnerability, err = mySQL.loadLayerIntroducingVulnerability(
		notification.OldVulnerability,
		limit,
		page.OldVulnerability,
	)

	if err != nil {
		return notification, page, err
	}

	page.NewVulnerability, err = mySQL.loadLayerIntroducingVulnerability(
		notification.NewVulnerability,
		limit,
		page.NewVulnerability,
	)

	if err != nil {
		return notification, page, err
	}

	return notification, page, nil
}

func (mySQL *mySQL) scanNotification(row *sql.Row, hasVulns bool) (database.VulnerabilityNotification, error) {
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
			vulnerability, err := mySQL.findVulnerabilityByIDWithDeleted(int(oldVulnerabilityNullableID.Int64))
			if err != nil {
				return notification, err
			}

			notification.OldVulnerability = &vulnerability
		}

		if newVulnerabilityNullableID.Valid {
			vulnerability, err := mySQL.findVulnerabilityByIDWithDeleted(int(newVulnerabilityNullableID.Int64))
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
func (mySQL *mySQL) loadLayerIntroducingVulnerability(vulnerability *database.Vulnerability, limit, startID int) (int, error) {
	tf := time.Now()

	if vulnerability == nil {
		return -1, nil
	}

	// A startID equals to -1 means that we reached the end already.
	if startID == -1 || limit == -1 {
		return -1, nil
	}

	// We do `defer database.ObserveQueryTime` here because we don't want to observe invalid calls.
	defer database.ObserveQueryTime("loadLayerIntroducingVulnerability", "all", tf)

	// Query with limit + 1, the last item will be used to know the next starting ID.
	rows, err := mySQL.Query(searchNotificationLayerIntroducingVulnerability,
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

func (mySQL *mySQL) SetNotificationNotified(name string) error {
	defer database.ObserveQueryTime("SetNotificationNotified", "all", time.Now())

	if _, err := mySQL.Exec(updatedNotificationNotified, name); err != nil {
		return handleError("updatedNotificationNotified", err)
	}
	return nil
}

func (mySQL *mySQL) DeleteNotification(name string) error {
	defer database.ObserveQueryTime("DeleteNotification", "all", time.Now())

	result, err := mySQL.Exec(removeNotification, name)
	if err != nil {
		return handleError("removeNotification", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return handleError("removeNotification.RowsAffected()", err)
	}

	if affected <= 0 {
		return cerrors.ErrNotFound
	}

	return nil
}
