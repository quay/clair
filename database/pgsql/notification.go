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
	"errors"
	"time"

	"github.com/guregu/null/zero"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/pkg/commonerr"
)

var (
	errNotificationNotFound = errors.New("requested notification is not found")
)

func (tx *pgSession) InsertVulnerabilityNotifications(notifications []database.VulnerabilityNotification) error {
	if len(notifications) == 0 {
		return nil
	}

	var (
		newVulnIDMap = make(map[database.VulnerabilityID]sql.NullInt64)
		oldVulnIDMap = make(map[database.VulnerabilityID]sql.NullInt64)
	)

	invalidCreationTime := time.Time{}
	for _, noti := range notifications {
		if noti.Name == "" {
			return commonerr.NewBadRequestError("notification should not have empty name")
		}
		if noti.Created == invalidCreationTime {
			return commonerr.NewBadRequestError("notification should not have empty created time")
		}

		if noti.New != nil {
			key := database.VulnerabilityID{
				Name:      noti.New.Name,
				Namespace: noti.New.Namespace.Name,
			}
			newVulnIDMap[key] = sql.NullInt64{}
		}

		if noti.Old != nil {
			key := database.VulnerabilityID{
				Name:      noti.Old.Name,
				Namespace: noti.Old.Namespace.Name,
			}
			oldVulnIDMap[key] = sql.NullInt64{}
		}
	}

	var (
		newVulnIDs = make([]database.VulnerabilityID, 0, len(newVulnIDMap))
		oldVulnIDs = make([]database.VulnerabilityID, 0, len(oldVulnIDMap))
	)

	for vulnID := range newVulnIDMap {
		newVulnIDs = append(newVulnIDs, vulnID)
	}

	for vulnID := range oldVulnIDMap {
		oldVulnIDs = append(oldVulnIDs, vulnID)
	}

	ids, err := tx.findNotDeletedVulnerabilityIDs(newVulnIDs)
	if err != nil {
		return err
	}

	for i, id := range ids {
		if !id.Valid {
			return handleError("findNotDeletedVulnerabilityIDs", errVulnerabilityNotFound)
		}
		newVulnIDMap[newVulnIDs[i]] = id
	}

	ids, err = tx.findLatestDeletedVulnerabilityIDs(oldVulnIDs)
	if err != nil {
		return err
	}

	for i, id := range ids {
		if !id.Valid {
			return handleError("findLatestDeletedVulnerabilityIDs", errVulnerabilityNotFound)
		}
		oldVulnIDMap[oldVulnIDs[i]] = id
	}

	var (
		newVulnID sql.NullInt64
		oldVulnID sql.NullInt64
	)

	keys := make([]interface{}, len(notifications)*4)
	for i, noti := range notifications {
		if noti.New != nil {
			newVulnID = newVulnIDMap[database.VulnerabilityID{
				Name:      noti.New.Name,
				Namespace: noti.New.Namespace.Name,
			}]
		}

		if noti.Old != nil {
			oldVulnID = oldVulnIDMap[database.VulnerabilityID{
				Name:      noti.Old.Name,
				Namespace: noti.Old.Namespace.Name,
			}]
		}

		keys[4*i] = noti.Name
		keys[4*i+1] = noti.Created
		keys[4*i+2] = oldVulnID
		keys[4*i+3] = newVulnID
	}

	// NOTE(Sida): The data is not sorted before inserting into database under
	// the fact that there's only one updater running at a time. If there are
	// multiple updaters, deadlock may happen.
	_, err = tx.Exec(queryInsertNotifications(len(notifications)), keys...)
	if err != nil {
		return handleError("queryInsertNotifications", err)
	}

	return nil
}

func (tx *pgSession) FindNewNotification(notifiedBefore time.Time) (database.NotificationHook, bool, error) {
	var (
		notification database.NotificationHook
		created      zero.Time
		notified     zero.Time
		deleted      zero.Time
	)

	err := tx.QueryRow(searchNotificationAvailable, notifiedBefore).Scan(&notification.Name, &created, &notified, &deleted)
	if err != nil {
		if err == sql.ErrNoRows {
			return notification, false, nil
		}
		return notification, false, handleError("searchNotificationAvailable", err)
	}

	notification.Created = created.Time
	notification.Notified = notified.Time
	notification.Deleted = deleted.Time

	return notification, true, nil
}

func (tx *pgSession) findPagedVulnerableAncestries(vulnID int64, limit int, currentPage database.PageNumber) (database.PagedVulnerableAncestries, error) {
	vulnPage := database.PagedVulnerableAncestries{Limit: limit}
	current := idPageNumber{0}
	if currentPage != "" {
		var err error
		current, err = decryptPage(currentPage, tx.paginationKey)
		if err != nil {
			return vulnPage, err
		}
	}

	err := tx.QueryRow(searchVulnerabilityByID, vulnID).Scan(
		&vulnPage.Name,
		&vulnPage.Description,
		&vulnPage.Link,
		&vulnPage.Severity,
		&vulnPage.Metadata,
		&vulnPage.Namespace.Name,
		&vulnPage.Namespace.VersionFormat,
	)
	if err != nil {
		return vulnPage, handleError("searchVulnerabilityByID", err)
	}

	// the last result is used for the next page's startID
	rows, err := tx.Query(searchNotificationVulnerableAncestry, vulnID, current.StartID, limit+1)
	if err != nil {
		return vulnPage, handleError("searchNotificationVulnerableAncestry", err)
	}
	defer rows.Close()

	ancestries := []affectedAncestry{}
	for rows.Next() {
		var ancestry affectedAncestry
		err := rows.Scan(&ancestry.id, &ancestry.name)
		if err != nil {
			return vulnPage, handleError("searchNotificationVulnerableAncestry", err)
		}
		ancestries = append(ancestries, ancestry)
	}

	lastIndex := 0
	if len(ancestries)-1 < limit {
		lastIndex = len(ancestries)
		vulnPage.End = true
	} else {
		// Use the last ancestry's ID as the next PageNumber.
		lastIndex = len(ancestries) - 1
		vulnPage.Next, err = encryptPage(
			idPageNumber{
				ancestries[len(ancestries)-1].id,
			}, tx.paginationKey)

		if err != nil {
			return vulnPage, err
		}
	}

	vulnPage.Affected = map[int]string{}
	for _, ancestry := range ancestries[0:lastIndex] {
		vulnPage.Affected[int(ancestry.id)] = ancestry.name
	}

	vulnPage.Current, err = encryptPage(current, tx.paginationKey)
	if err != nil {
		return vulnPage, err
	}

	return vulnPage, nil
}

func (tx *pgSession) FindVulnerabilityNotification(name string, limit int, oldPage database.PageNumber, newPage database.PageNumber) (
	database.VulnerabilityNotificationWithVulnerable, bool, error) {
	var (
		noti      database.VulnerabilityNotificationWithVulnerable
		oldVulnID sql.NullInt64
		newVulnID sql.NullInt64
		created   zero.Time
		notified  zero.Time
		deleted   zero.Time
	)

	if name == "" {
		return noti, false, commonerr.NewBadRequestError("Empty notification name is not allowed")
	}

	noti.Name = name

	err := tx.QueryRow(searchNotification, name).Scan(&created, &notified,
		&deleted, &oldVulnID, &newVulnID)

	if err != nil {
		if err == sql.ErrNoRows {
			return noti, false, nil
		}
		return noti, false, handleError("searchNotification", err)
	}

	if created.Valid {
		noti.Created = created.Time
	}

	if notified.Valid {
		noti.Notified = notified.Time
	}

	if deleted.Valid {
		noti.Deleted = deleted.Time
	}

	if oldVulnID.Valid {
		page, err := tx.findPagedVulnerableAncestries(oldVulnID.Int64, limit, oldPage)
		if err != nil {
			return noti, false, err
		}
		noti.Old = &page
	}

	if newVulnID.Valid {
		page, err := tx.findPagedVulnerableAncestries(newVulnID.Int64, limit, newPage)
		if err != nil {
			return noti, false, err
		}
		noti.New = &page
	}

	return noti, true, nil
}

func (tx *pgSession) MarkNotificationNotified(name string) error {
	if name == "" {
		return commonerr.NewBadRequestError("Empty notification name is not allowed")
	}

	r, err := tx.Exec(updatedNotificationNotified, name)
	if err != nil {
		return handleError("updatedNotificationNotified", err)
	}

	affected, err := r.RowsAffected()
	if err != nil {
		return handleError("updatedNotificationNotified", err)
	}

	if affected <= 0 {
		return handleError("updatedNotificationNotified", errNotificationNotFound)
	}
	return nil
}

func (tx *pgSession) DeleteNotification(name string) error {
	if name == "" {
		return commonerr.NewBadRequestError("Empty notification name is not allowed")
	}

	result, err := tx.Exec(removeNotification, name)
	if err != nil {
		return handleError("removeNotification", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return handleError("removeNotification", err)
	}

	if affected <= 0 {
		return handleError("removeNotification", commonerr.ErrNotFound)
	}

	return nil
}
