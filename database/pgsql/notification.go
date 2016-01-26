package pgsql

import (
	"database/sql"
	"encoding/json"
	"time"

	"github.com/coreos/clair/database"
	cerrors "github.com/coreos/clair/utils/errors"
	"github.com/guregu/null/zero"
	"github.com/pborman/uuid"
)

// do it in tx so we won't insert/update a vuln without notification and vice-versa.
// name and created doesn't matter.
// Vuln ID must be filled in.
func (pgSQL *pgSQL) insertNotification(tx *sql.Tx, notification database.VulnerabilityNotification) error {
	defer observeQueryTime("insertNotification", "all", time.Now())

	// Marshal old and new Vulnerabilities.
	var oldVulnerability sql.NullString
	if notification.OldVulnerability != nil {
		oldVulnerabilityJSON, err := json.Marshal(notification.OldVulnerability)
		if err != nil {
			tx.Rollback()
			return cerrors.NewBadRequestError("could not marshal old Vulnerability in insertNotification")
		}
		oldVulnerability = sql.NullString{String: string(oldVulnerabilityJSON), Valid: true}
	}

	newVulnerability, err := json.Marshal(notification.NewVulnerability)
	if err != nil {
		tx.Rollback()
		return cerrors.NewBadRequestError("could not marshal new Vulnerability in insertNotification")
	}

	// Insert Notification.
	_, err = tx.Exec(getQuery("i_notification"), uuid.New(), oldVulnerability, newVulnerability)
	if err != nil {
		tx.Rollback()
		return handleError("i_notification", err)
	}

	return nil
}

// Get one available notification name (!locked && !deleted && (!notified || notified_but_timed-out)).
// Does not fill new/old vuln.
func (pgSQL *pgSQL) GetAvailableNotification(renotifyInterval time.Duration) (database.VulnerabilityNotification, error) {
	defer observeQueryTime("GetAvailableNotification", "all", time.Now())

	before := time.Now().Add(-renotifyInterval)
	row := pgSQL.QueryRow(getQuery("s_notification_available"), before)
	notification, err := scanNotification(row, false)

	return notification, handleError("s_notification_available", err)
}

func (pgSQL *pgSQL) GetNotification(name string, limit int, page database.VulnerabilityNotificationPageNumber) (database.VulnerabilityNotification, database.VulnerabilityNotificationPageNumber, error) {
	defer observeQueryTime("GetNotification", "all", time.Now())

	// Get Notification.
	notification, err := scanNotification(pgSQL.QueryRow(getQuery("s_notification"), name), true)
	if err != nil {
		return notification, page, handleError("s_notification", err)
	}

	// Load vulnerabilities' LayersIntroducingVulnerability.
	page.OldVulnerability, err = pgSQL.loadLayerIntroducingVulnerability(
		notification.OldVulnerability, limit, page.OldVulnerability)
	if err != nil {
		return notification, page, err
	}

	page.NewVulnerability, err = pgSQL.loadLayerIntroducingVulnerability(
		&notification.NewVulnerability, limit, page.NewVulnerability)
	if err != nil {
		return notification, page, err
	}

	return notification, page, nil
}

func scanNotification(row *sql.Row, hasVulns bool) (notification database.VulnerabilityNotification, err error) {
	var created zero.Time
	var notified zero.Time
	var deleted zero.Time
	var oldVulnerability []byte
	var newVulnerability []byte

	// Query notification.
	if hasVulns {
		err = row.Scan(&notification.ID, &notification.Name, &created, &notified, &deleted,
			&oldVulnerability, &newVulnerability)
	} else {
		err = row.Scan(&notification.ID, &notification.Name, &created, &notified, &deleted)
	}
	if err != nil {
		return
	}

	notification.Created = created.Time
	notification.Notified = notified.Time
	notification.Deleted = deleted.Time

	if hasVulns {
		// Unmarshal old and new Vulnerabilities.
		err = json.Unmarshal(oldVulnerability, notification.OldVulnerability)
		if err != nil {
			err = cerrors.NewBadRequestError("could not unmarshal old Vulnerability in GetNotification")
		}

		err = json.Unmarshal(newVulnerability, &notification.NewVulnerability)
		if err != nil {
			err = cerrors.NewBadRequestError("could not unmarshal new Vulnerability in GetNotification")
		}
	}

	return
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

	// We do `defer observeQueryTime` here because we don't want to observe invalid calls.
	defer observeQueryTime("loadLayerIntroducingVulnerability", "all", tf)

	// Query with limit + 1, the last item will be used to know the next starting ID.
	rows, err := pgSQL.Query(getQuery("s_notification_layer_introducing_vulnerability"),
		vulnerability.ID, startID, limit+1)
	if err != nil {
		return 0, handleError("s_vulnerability_fixedin_feature", err)
	}
	defer rows.Close()

	var layers []database.Layer
	for rows.Next() {
		var layer database.Layer

		if err := rows.Scan(&layer.ID, &layer.Name); err != nil {
			return -1, handleError("s_notification_layer_introducing_vulnerability.Scan()", err)
		}

		layers = append(layers, layer)
	}
	if err = rows.Err(); err != nil {
		return -1, handleError("s_notification_layer_introducing_vulnerability.Rows()", err)
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

	if _, err := pgSQL.Exec(getQuery("u_notification_notified"), name); err != nil {
		return handleError("u_notification_notified", err)
	}
	return nil
}

func (pgSQL *pgSQL) DeleteNotification(name string) error {
	defer observeQueryTime("DeleteNotification", "all", time.Now())

	result, err := pgSQL.Exec(getQuery("r_notification"), name)
	if err != nil {
		return handleError("r_notification", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return handleError("r_notification.RowsAffected()", err)
	}

	if affected <= 0 {
		return cerrors.ErrNotFound
	}

	return nil
}
