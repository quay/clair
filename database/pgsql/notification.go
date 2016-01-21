package pgsql

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"reflect"
	"time"

	"github.com/coreos/clair/database"
	cerrors "github.com/coreos/clair/utils/errors"
	"github.com/pborman/uuid"
)

// do it in tx so we won't insert/update a vuln without notification and vice-versa.
func (pgSQL *pgSQL) insertNotification(tx *sql.Tx, notification interface{}) error {
	kind := reflect.Indirect(reflect.ValueOf(notification)).Type().String()
	data, err := json.Marshal(notification)
	if err != nil {
		tx.Rollback()
		return cerrors.NewBadRequestError("could not marshal notification in insertNotification")
	}

	_, err = tx.Exec(getQuery("i_notification"), uuid.New(), kind, data)
	if err != nil {
		tx.Rollback()
		return handleError("i_notification", err)
	}

	return nil
}

func (pgSQL *pgSQL) CountAvailableNotifications() (int, error) {
	var count int
	err := pgSQL.QueryRow(getQuery("c_notification_available")).Scan(&count)
	if err != nil {
		return 0, handleError("c_notification_available", err)
	}

	return count, nil
}

// Get one available notification (!locked && !deleted && (!notified || notified_but_timed-out)).
func (pgSQL *pgSQL) GetAvailableNotification(renotifyInterval time.Duration) (string, error) {
	before := time.Now().Add(-renotifyInterval)

	var name string
	err := pgSQL.QueryRow(getQuery("s_notification_available"), before).Scan(&name)
	if err != nil {
		return "", handleError("s_notification_available", err)
	}

	return name, nil
}

func (pgSQL *pgSQL) GetNotification(name string, limit, page int) (string, interface{}, error) {
	var kind, data string
	err := pgSQL.QueryRow(getQuery("s_notification"), name).Scan(&kind, &data)
	if err != nil {
		return "", struct{}{}, handleError("s_notification", err)
	}

	return constructNotification(kind, data, limit, page)
}

func constructNotification(kind, data string, limit, page int) (string, interface{}, error) {
	switch kind {
	case "NotificationNewVulnerability":
		var notificationPage database.NewVulnerabilityNotificationPage

		// TODO: Request database to fill NewVulnerabilityNotificationPage properly.

		return kind, notificationPage, nil
	default:
		msg := fmt.Sprintf("could not construct notification, '%s' is an unknown notification type", kind)
		return "", struct{}{}, cerrors.NewBadRequestError(msg)
	}
}

func (pgSQL *pgSQL) SetNotificationNotified(name string) error {
	if _, err := pgSQL.Exec(getQuery("u_notification_notified"), name); err != nil {
		return handleError("u_notification_notified", err)
	}
	return nil
}

func (pgSQL *pgSQL) DeleteNotification(name string) error {
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
