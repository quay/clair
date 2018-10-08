// Copyright 2018 clair authors
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
	"github.com/stretchr/testify/require"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/pkg/pagination"
)

type findVulnerabilityNotificationIn struct {
	notificationName        string
	pageSize                int
	oldAffectedAncestryPage pagination.Token
	newAffectedAncestryPage pagination.Token
}

type findVulnerabilityNotificationOut struct {
	notification *database.VulnerabilityNotificationWithVulnerable
	ok           bool
	err          string
}

var findVulnerabilityNotificationTests = []struct {
	title string
	in    findVulnerabilityNotificationIn
	out   findVulnerabilityNotificationOut
}{
	{
		title: "find notification with invalid page",
		in: findVulnerabilityNotificationIn{
			notificationName:        "test",
			pageSize:                1,
			oldAffectedAncestryPage: pagination.FirstPageToken,
			newAffectedAncestryPage: pagination.Token("random non sense"),
		},
		out: findVulnerabilityNotificationOut{
			err: pagination.ErrInvalidToken.Error(),
		},
	},
	{
		title: "find non-existing notification",
		in: findVulnerabilityNotificationIn{
			notificationName:        "non-existing",
			pageSize:                1,
			oldAffectedAncestryPage: pagination.FirstPageToken,
			newAffectedAncestryPage: pagination.FirstPageToken,
		},
		out: findVulnerabilityNotificationOut{
			ok: false,
		},
	},
	{
		title: "find existing notification first page",
		in: findVulnerabilityNotificationIn{
			notificationName:        "test",
			pageSize:                1,
			oldAffectedAncestryPage: pagination.FirstPageToken,
			newAffectedAncestryPage: pagination.FirstPageToken,
		},
		out: findVulnerabilityNotificationOut{
			&database.VulnerabilityNotificationWithVulnerable{
				NotificationHook: realNotification[1].NotificationHook,
				Old: &database.PagedVulnerableAncestries{
					Vulnerability: realVulnerability[2],
					Limit:         1,
					Affected:      make(map[int]string),
					Current:       mustMarshalToken(testPaginationKey, Page{0}),
					Next:          mustMarshalToken(testPaginationKey, Page{0}),
					End:           true,
				},
				New: &database.PagedVulnerableAncestries{
					Vulnerability: realVulnerability[1],
					Limit:         1,
					Affected:      map[int]string{3: "ancestry-3"},
					Current:       mustMarshalToken(testPaginationKey, Page{0}),
					Next:          mustMarshalToken(testPaginationKey, Page{4}),
					End:           false,
				},
			},

			true,
			"",
		},
	},

	{
		title: "find existing notification of second page of new affected ancestry",
		in: findVulnerabilityNotificationIn{
			notificationName:        "test",
			pageSize:                1,
			oldAffectedAncestryPage: pagination.FirstPageToken,
			newAffectedAncestryPage: mustMarshalToken(testPaginationKey, Page{4}),
		},
		out: findVulnerabilityNotificationOut{
			&database.VulnerabilityNotificationWithVulnerable{
				NotificationHook: realNotification[1].NotificationHook,
				Old: &database.PagedVulnerableAncestries{
					Vulnerability: realVulnerability[2],
					Limit:         1,
					Affected:      make(map[int]string),
					Current:       mustMarshalToken(testPaginationKey, Page{0}),
					Next:          mustMarshalToken(testPaginationKey, Page{0}),
					End:           true,
				},
				New: &database.PagedVulnerableAncestries{
					Vulnerability: realVulnerability[1],
					Limit:         1,
					Affected:      map[int]string{4: "ancestry-4"},
					Current:       mustMarshalToken(testPaginationKey, Page{4}),
					Next:          mustMarshalToken(testPaginationKey, Page{0}),
					End:           true,
				},
			},

			true,
			"",
		},
	},
}

func TestFindVulnerabilityNotification(t *testing.T) {
	datastore, tx := openSessionForTest(t, "pagination", true)
	defer closeTest(t, datastore, tx)

	for _, test := range findVulnerabilityNotificationTests {
		t.Run(test.title, func(t *testing.T) {
			notification, ok, err := tx.FindVulnerabilityNotification(test.in.notificationName, test.in.pageSize, test.in.oldAffectedAncestryPage, test.in.newAffectedAncestryPage)
			if test.out.err != "" {
				require.EqualError(t, err, test.out.err)
				return
			}

			require.Nil(t, err)
			if !test.out.ok {
				require.Equal(t, test.out.ok, ok)
				return
			}

			require.True(t, ok)
			assertVulnerabilityNotificationWithVulnerableEqual(t, testPaginationKey, test.out.notification, &notification)
		})
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
	assert.Nil(t, tx.MarkNotificationAsRead("test"))
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

func TestMarkNotificationAsRead(t *testing.T) {
	datastore, tx := openSessionForTest(t, "MarkNotificationAsRead", true)
	defer closeTest(t, datastore, tx)

	// invalid case: notification doesn't exist
	assert.NotNil(t, tx.MarkNotificationAsRead("non-existing"))
	// valid case
	assert.Nil(t, tx.MarkNotificationAsRead("test"))
	// valid case
	assert.Nil(t, tx.MarkNotificationAsRead("test"))
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
