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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/coreos/clair/database"
)

func TestPagination(t *testing.T) {
	datastore, tx := openSessionForTest(t, "Pagination", true)
	defer closeTest(t, datastore, tx)

	ns := database.Namespace{
		Name:          "debian:7",
		VersionFormat: "dpkg",
	}

	vNew := database.Vulnerability{
		Namespace:   ns,
		Name:        "CVE-OPENSSL-1-DEB7",
		Description: "A vulnerability affecting OpenSSL < 2.0 on Debian 7.0",
		Link:        "http://google.com/#q=CVE-OPENSSL-1-DEB7",
		Severity:    database.HighSeverity,
	}

	vOld := database.Vulnerability{
		Namespace:   ns,
		Name:        "CVE-NOPE",
		Description: "A vulnerability affecting nothing",
		Severity:    database.UnknownSeverity,
	}

	noti, ok, err := tx.FindVulnerabilityNotification("test", 1, "", "")
	oldPage := database.PagedVulnerableAncestries{
		Vulnerability: vOld,
		Limit:         1,
		Affected:      make(map[int]string),
		End:           true,
	}

	newPage1 := database.PagedVulnerableAncestries{
		Vulnerability: vNew,
		Limit:         1,
		Affected:      map[int]string{3: "ancestry-3"},
		End:           false,
	}

	newPage2 := database.PagedVulnerableAncestries{
		Vulnerability: vNew,
		Limit:         1,
		Affected:      map[int]string{4: "ancestry-4"},
		Next:          "",
		End:           true,
	}

	if assert.Nil(t, err) && assert.True(t, ok) {
		assert.Equal(t, "test", noti.Name)
		if assert.NotNil(t, noti.Old) && assert.NotNil(t, noti.New) {
			oldPageNum, err := decryptPage(noti.Old.Current, tx.paginationKey)
			if !assert.Nil(t, err) {
				assert.FailNow(t, "")
			}

			assert.Equal(t, int64(0), oldPageNum.StartID)
			newPageNum, err := decryptPage(noti.New.Current, tx.paginationKey)
			if !assert.Nil(t, err) {
				assert.FailNow(t, "")
			}
			newPageNextNum, err := decryptPage(noti.New.Next, tx.paginationKey)
			if !assert.Nil(t, err) {
				assert.FailNow(t, "")
			}
			assert.Equal(t, int64(0), newPageNum.StartID)
			assert.Equal(t, int64(4), newPageNextNum.StartID)

			noti.Old.Current = ""
			noti.New.Current = ""
			noti.New.Next = ""
			assert.Equal(t, oldPage, *noti.Old)
			assert.Equal(t, newPage1, *noti.New)
		}
	}

	page1, err := encryptPage(idPageNumber{0}, tx.paginationKey)
	if !assert.Nil(t, err) {
		assert.FailNow(t, "")
	}

	page2, err := encryptPage(idPageNumber{4}, tx.paginationKey)
	if !assert.Nil(t, err) {
		assert.FailNow(t, "")
	}

	noti, ok, err = tx.FindVulnerabilityNotification("test", 1, page1, page2)
	if assert.Nil(t, err) && assert.True(t, ok) {
		assert.Equal(t, "test", noti.Name)
		if assert.NotNil(t, noti.Old) && assert.NotNil(t, noti.New) {
			oldCurrentPage, err := decryptPage(noti.Old.Current, tx.paginationKey)
			if !assert.Nil(t, err) {
				assert.FailNow(t, "")
			}

			newCurrentPage, err := decryptPage(noti.New.Current, tx.paginationKey)
			if !assert.Nil(t, err) {
				assert.FailNow(t, "")
			}

			assert.Equal(t, int64(0), oldCurrentPage.StartID)
			assert.Equal(t, int64(4), newCurrentPage.StartID)
			noti.Old.Current = ""
			noti.New.Current = ""
			assert.Equal(t, oldPage, *noti.Old)
			assert.Equal(t, newPage2, *noti.New)
		}
	}
}

func TestInsertVulnerabilityNotifications(t *testing.T) {
	datastore, tx := openSessionForTest(t, "InsertVulnerabilityNotifications", true)

	n1 := database.VulnerabilityNotification{}
	n3 := database.VulnerabilityNotification{
		NotificationHook: database.NotificationHook{
			Name:    "random name",
			Created: time.Now(),
		},
		Old: nil,
		New: &database.Vulnerability{},
	}
	n4 := database.VulnerabilityNotification{
		NotificationHook: database.NotificationHook{
			Name:    "random name",
			Created: time.Now(),
		},
		Old: nil,
		New: &database.Vulnerability{
			Name: "CVE-OPENSSL-1-DEB7",
			Namespace: database.Namespace{
				Name:          "debian:7",
				VersionFormat: "dpkg",
			},
		},
	}

	// invalid case
	err := tx.InsertVulnerabilityNotifications([]database.VulnerabilityNotification{n1})
	assert.NotNil(t, err)

	// invalid case: unknown vulnerability
	err = tx.InsertVulnerabilityNotifications([]database.VulnerabilityNotification{n3})
	assert.NotNil(t, err)

	// invalid case: duplicated input notification
	err = tx.InsertVulnerabilityNotifications([]database.VulnerabilityNotification{n4, n4})
	assert.NotNil(t, err)
	tx = restartSession(t, datastore, tx, false)

	// valid case
	err = tx.InsertVulnerabilityNotifications([]database.VulnerabilityNotification{n4})
	assert.Nil(t, err)
	// invalid case: notification is already in database
	err = tx.InsertVulnerabilityNotifications([]database.VulnerabilityNotification{n4})
	assert.NotNil(t, err)

	closeTest(t, datastore, tx)
}

func TestFindNewNotification(t *testing.T) {
	datastore, tx := openSessionForTest(t, "FindNewNotification", true)
	defer closeTest(t, datastore, tx)

	noti, ok, err := tx.FindNewNotification(time.Now())
	if assert.Nil(t, err) && assert.True(t, ok) {
		assert.Equal(t, "test", noti.Name)
		assert.Equal(t, time.Time{}, noti.Notified)
		assert.Equal(t, time.Time{}, noti.Created)
		assert.Equal(t, time.Time{}, noti.Deleted)
	}

	// can't find the notified
	assert.Nil(t, tx.MarkNotificationNotified("test"))
	// if the notified time is before
	noti, ok, err = tx.FindNewNotification(time.Now().Add(-time.Duration(10 * time.Second)))
	assert.Nil(t, err)
	assert.False(t, ok)
	// can find the notified after a period of time
	noti, ok, err = tx.FindNewNotification(time.Now().Add(time.Duration(1000)))
	if assert.Nil(t, err) && assert.True(t, ok) {
		assert.Equal(t, "test", noti.Name)
		assert.NotEqual(t, time.Time{}, noti.Notified)
		assert.Equal(t, time.Time{}, noti.Created)
		assert.Equal(t, time.Time{}, noti.Deleted)
	}

	assert.Nil(t, tx.DeleteNotification("test"))
	// can't find in any time
	noti, ok, err = tx.FindNewNotification(time.Now().Add(-time.Duration(1000)))
	assert.Nil(t, err)
	assert.False(t, ok)

	noti, ok, err = tx.FindNewNotification(time.Now().Add(time.Duration(1000)))
	assert.Nil(t, err)
	assert.False(t, ok)
}

func TestMarkNotificationNotified(t *testing.T) {
	datastore, tx := openSessionForTest(t, "MarkNotificationNotified", true)
	defer closeTest(t, datastore, tx)

	// invalid case: notification doesn't exist
	assert.NotNil(t, tx.MarkNotificationNotified("non-existing"))
	// valid case
	assert.Nil(t, tx.MarkNotificationNotified("test"))
	// valid case
	assert.Nil(t, tx.MarkNotificationNotified("test"))
}

func TestDeleteNotification(t *testing.T) {
	datastore, tx := openSessionForTest(t, "DeleteNotification", true)
	defer closeTest(t, datastore, tx)

	// invalid case: notification doesn't exist
	assert.NotNil(t, tx.DeleteNotification("non-existing"))
	// valid case
	assert.Nil(t, tx.DeleteNotification("test"))
	// invalid case: notification is already deleted
	assert.NotNil(t, tx.DeleteNotification("test"))
}
