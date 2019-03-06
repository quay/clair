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

package notification

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/database/pgsql/page"
	"github.com/coreos/clair/database/pgsql/testutil"
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

var testPaginationKey = pagination.Must(pagination.NewKey())

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
				NotificationHook: testutil.RealNotification[1].NotificationHook,
				Old: &database.PagedVulnerableAncestries{
					Vulnerability: testutil.RealVulnerability[2],
					Limit:         1,
					Affected:      make(map[int]string),
					Current:       testutil.MustMarshalToken(testutil.TestPaginationKey, page.Page{0}),
					Next:          testutil.MustMarshalToken(testutil.TestPaginationKey, page.Page{0}),
					End:           true,
				},
				New: &database.PagedVulnerableAncestries{
					Vulnerability: testutil.RealVulnerability[1],
					Limit:         1,
					Affected:      map[int]string{3: "ancestry-3"},
					Current:       testutil.MustMarshalToken(testutil.TestPaginationKey, page.Page{0}),
					Next:          testutil.MustMarshalToken(testutil.TestPaginationKey, page.Page{4}),
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
			newAffectedAncestryPage: testutil.MustMarshalToken(testutil.TestPaginationKey, page.Page{4}),
		},
		out: findVulnerabilityNotificationOut{
			&database.VulnerabilityNotificationWithVulnerable{
				NotificationHook: testutil.RealNotification[1].NotificationHook,
				Old: &database.PagedVulnerableAncestries{
					Vulnerability: testutil.RealVulnerability[2],
					Limit:         1,
					Affected:      make(map[int]string),
					Current:       testutil.MustMarshalToken(testutil.TestPaginationKey, page.Page{0}),
					Next:          testutil.MustMarshalToken(testutil.TestPaginationKey, page.Page{0}),
					End:           true,
				},
				New: &database.PagedVulnerableAncestries{
					Vulnerability: testutil.RealVulnerability[1],
					Limit:         1,
					Affected:      map[int]string{4: "ancestry-4"},
					Current:       testutil.MustMarshalToken(testutil.TestPaginationKey, page.Page{4}),
					Next:          testutil.MustMarshalToken(testutil.TestPaginationKey, page.Page{0}),
					End:           true,
				},
			},

			true,
			"",
		},
	},
}

func TestFindVulnerabilityNotification(t *testing.T) {
	tx, cleanup := testutil.CreateTestTxWithFixtures(t, "pagination")
	defer cleanup()

	for _, test := range findVulnerabilityNotificationTests {
		t.Run(test.title, func(t *testing.T) {
			notification, ok, err := FindVulnerabilityNotification(tx, test.in.notificationName, test.in.pageSize, test.in.oldAffectedAncestryPage, test.in.newAffectedAncestryPage, testutil.TestPaginationKey)
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
			testutil.AssertVulnerabilityNotificationWithVulnerableEqual(t, testutil.TestPaginationKey, test.out.notification, &notification)
		})
	}
}

func TestInsertVulnerabilityNotifications(t *testing.T) {
	datastore, cleanup := testutil.CreateTestDBWithFixture(t, "InsertVulnerabilityNotifications")
	defer cleanup()

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

	tx, err := datastore.Begin()
	require.Nil(t, err)

	// invalid case
	err = InsertVulnerabilityNotifications(tx, []database.VulnerabilityNotification{n1})
	require.NotNil(t, err)

	// invalid case: unknown vulnerability
	err = InsertVulnerabilityNotifications(tx, []database.VulnerabilityNotification{n3})
	require.NotNil(t, err)

	// invalid case: duplicated input notification
	err = InsertVulnerabilityNotifications(tx, []database.VulnerabilityNotification{n4, n4})
	require.NotNil(t, err)
	tx = testutil.RestartTransaction(datastore, tx, false)

	// valid case
	err = InsertVulnerabilityNotifications(tx, []database.VulnerabilityNotification{n4})
	require.Nil(t, err)
	// invalid case: notification is already in database
	err = InsertVulnerabilityNotifications(tx, []database.VulnerabilityNotification{n4})
	require.NotNil(t, err)

	require.Nil(t, tx.Rollback())
}

func TestFindNewNotification(t *testing.T) {
	tx, cleanup := testutil.CreateTestTxWithFixtures(t, "TestFindNewNotification")
	defer cleanup()

	noti, ok, err := FindNewNotification(tx, time.Now())
	if assert.Nil(t, err) && assert.True(t, ok) {
		assert.Equal(t, "test", noti.Name)
		assert.Equal(t, time.Time{}, noti.Notified)
		assert.Equal(t, time.Time{}, noti.Created)
		assert.Equal(t, time.Time{}, noti.Deleted)
	}

	// can't find the notified
	assert.Nil(t, MarkNotificationAsRead(tx, "test"))
	// if the notified time is before
	noti, ok, err = FindNewNotification(tx, time.Now().Add(-time.Duration(10*time.Second)))
	assert.Nil(t, err)
	assert.False(t, ok)
	// can find the notified after a period of time
	noti, ok, err = FindNewNotification(tx, time.Now().Add(time.Duration(10*time.Second)))
	if assert.Nil(t, err) && assert.True(t, ok) {
		assert.Equal(t, "test", noti.Name)
		assert.NotEqual(t, time.Time{}, noti.Notified)
		assert.Equal(t, time.Time{}, noti.Created)
		assert.Equal(t, time.Time{}, noti.Deleted)
	}

	assert.Nil(t, DeleteNotification(tx, "test"))
	// can't find in any time
	noti, ok, err = FindNewNotification(tx, time.Now().Add(-time.Duration(1000)))
	assert.Nil(t, err)
	assert.False(t, ok)

	noti, ok, err = FindNewNotification(tx, time.Now().Add(time.Duration(1000)))
	assert.Nil(t, err)
	assert.False(t, ok)
}

func TestMarkNotificationAsRead(t *testing.T) {
	tx, cleanup := testutil.CreateTestTxWithFixtures(t, "MarkNotificationAsRead")
	defer cleanup()

	// invalid case: notification doesn't exist
	assert.NotNil(t, MarkNotificationAsRead(tx, "non-existing"))
	// valid case
	assert.Nil(t, MarkNotificationAsRead(tx, "test"))
	// valid case
	assert.Nil(t, MarkNotificationAsRead(tx, "test"))
}

func TestDeleteNotification(t *testing.T) {
	tx, cleanup := testutil.CreateTestTxWithFixtures(t, "DeleteNotification")
	defer cleanup()

	// invalid case: notification doesn't exist
	assert.NotNil(t, DeleteNotification(tx, "non-existing"))
	// valid case
	assert.Nil(t, DeleteNotification(tx, "test"))
	// invalid case: notification is already deleted
	assert.NotNil(t, DeleteNotification(tx, "test"))
}
