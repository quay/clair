package pgsql

import (
	"database/sql"
	"encoding/json"
	"time"

	"github.com/coreos/clair/database"
	cerrors "github.com/coreos/clair/utils/errors"
	"github.com/pborman/uuid"
)

// do it in tx so we won't insert/update a vuln without notification and vice-versa.
// name and created doesn't matter.
func (pgSQL *pgSQL) insertNotification(tx *sql.Tx, notification database.VulnerabilityNotification) error {
	defer observeQueryTime("insertNotification", "all", time.Now())

	// Marshal old and new Vulnerabilities.
	oldVulnerability, err := json.Marshal(notification.OldVulnerability)
	if err != nil {
		tx.Rollback()
		return cerrors.NewBadRequestError("could not marshal old Vulnerability in insertNotification")
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

	var notification database.VulnerabilityNotification
	err := pgSQL.QueryRow(getQuery("s_notification_available"), before).Scan(&notification.Name,
		&notification.Created, &notification.Notified, &notification.Deleted)
	if err != nil {
		return notification, handleError("s_notification_available", err)
	}

	return notification, nil
}

func (pgSQL *pgSQL) GetNotification(name string, limit, page int) (database.VulnerabilityNotification, error) {
	defer observeQueryTime("GetNotification", "all", time.Now())

	// Get Notification.
	var notification database.VulnerabilityNotification
	var oldVulnerability []byte
	var newVulnerability []byte

	err := pgSQL.QueryRow(getQuery("s_notification"), name).Scan(&notification.Name,
		&notification.Created, &notification.Notified, &notification.Deleted, &newVulnerability,
		&oldVulnerability)
	if err != nil {
		return notification, handleError("s_notification", err)
	}

	// Unmarshal old and new Vulnerabilities.
	err = json.Unmarshal(oldVulnerability, notification.OldVulnerability)
	if err != nil {
		return notification, cerrors.NewBadRequestError("could not unmarshal old Vulnerability in GetNotification")
	}
	err = json.Unmarshal(newVulnerability, &notification.NewVulnerability)
	if err != nil {
		return notification, cerrors.NewBadRequestError("could not unmarshal new Vulnerability in GetNotification")
	}

	// TODO(Quentin-M): Fill LayersIntroducingVulnerability.
	// And time it.

	return notification, nil
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
