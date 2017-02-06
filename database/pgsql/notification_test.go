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
	"github.com/coreos/clair/ext/versionfmt"
	"github.com/coreos/clair/ext/versionfmt/dpkg"
	"github.com/coreos/clair/pkg/commonerr"
)

func TestNotification(t *testing.T) {
	datastore, err := openDatabaseForTest("Notification", false)
	if err != nil {
		t.Error(err)
		return
	}
	defer datastore.Close()

	// Try to get a notification when there is none.
	_, err = datastore.GetAvailableNotification(time.Second)
	assert.Equal(t, commonerr.ErrNotFound, err)

	// Create some data.
	f1 := database.Feature{
		Name: "TestNotificationFeature1",
		Namespace: database.Namespace{
			Name:          "TestNotificationNamespace1",
			VersionFormat: dpkg.ParserName,
		},
	}

	f2 := database.Feature{
		Name: "TestNotificationFeature2",
		Namespace: database.Namespace{
			Name:          "TestNotificationNamespace1",
			VersionFormat: dpkg.ParserName,
		},
	}

	l1 := database.Layer{
		Name: "TestNotificationLayer1",
		Features: []database.FeatureVersion{
			{
				Feature: f1,
				Version: "0.1",
			},
		},
	}

	l2 := database.Layer{
		Name: "TestNotificationLayer2",
		Features: []database.FeatureVersion{
			{
				Feature: f1,
				Version: "0.2",
			},
		},
	}

	l3 := database.Layer{
		Name: "TestNotificationLayer3",
		Features: []database.FeatureVersion{
			{
				Feature: f1,
				Version: "0.3",
			},
		},
	}

	l4 := database.Layer{
		Name: "TestNotificationLayer4",
		Features: []database.FeatureVersion{
			{
				Feature: f2,
				Version: "0.1",
			},
		},
	}

	if !assert.Nil(t, datastore.InsertLayer(l1)) ||
		!assert.Nil(t, datastore.InsertLayer(l2)) ||
		!assert.Nil(t, datastore.InsertLayer(l3)) ||
		!assert.Nil(t, datastore.InsertLayer(l4)) {
		return
	}

	// Insert a new vulnerability that is introduced by three layers.
	v1 := database.Vulnerability{
		Name:        "TestNotificationVulnerability1",
		Namespace:   f1.Namespace,
		Description: "TestNotificationDescription1",
		Link:        "TestNotificationLink1",
		Severity:    "Unknown",
		FixedIn: []database.FeatureVersion{
			{
				Feature: f1,
				Version: "1.0",
			},
		},
	}
	assert.Nil(t, datastore.insertVulnerability(v1, false, true))

	// Get the notification associated to the previously inserted vulnerability.
	notification, err := datastore.GetAvailableNotification(time.Second)

	if assert.Nil(t, err) && assert.NotEmpty(t, notification.Name) {
		// Verify the renotify behaviour.
		if assert.Nil(t, datastore.SetNotificationNotified(notification.Name)) {
			_, err := datastore.GetAvailableNotification(time.Second)
			assert.Equal(t, commonerr.ErrNotFound, err)

			time.Sleep(50 * time.Millisecond)
			notificationB, err := datastore.GetAvailableNotification(20 * time.Millisecond)
			assert.Nil(t, err)
			assert.Equal(t, notification.Name, notificationB.Name)

			datastore.SetNotificationNotified(notification.Name)
		}

		// Get notification.
		filledNotification, nextPage, err := datastore.GetNotification(notification.Name, 2, database.VulnerabilityNotificationFirstPage)
		if assert.Nil(t, err) {
			assert.NotEqual(t, database.NoVulnerabilityNotificationPage, nextPage)
			assert.Nil(t, filledNotification.OldVulnerability)

			if assert.NotNil(t, filledNotification.NewVulnerability) {
				assert.Equal(t, v1.Name, filledNotification.NewVulnerability.Name)
				assert.Len(t, filledNotification.NewVulnerability.LayersIntroducingVulnerability, 2)
			}
		}

		// Get second page.
		filledNotification, nextPage, err = datastore.GetNotification(notification.Name, 2, nextPage)
		if assert.Nil(t, err) {
			assert.Equal(t, database.NoVulnerabilityNotificationPage, nextPage)
			assert.Nil(t, filledNotification.OldVulnerability)

			if assert.NotNil(t, filledNotification.NewVulnerability) {
				assert.Equal(t, v1.Name, filledNotification.NewVulnerability.Name)
				assert.Len(t, filledNotification.NewVulnerability.LayersIntroducingVulnerability, 1)
			}
		}

		// Delete notification.
		assert.Nil(t, datastore.DeleteNotification(notification.Name))

		_, err = datastore.GetAvailableNotification(time.Millisecond)
		assert.Equal(t, commonerr.ErrNotFound, err)
	}

	// Update a vulnerability and ensure that the old/new vulnerabilities are correct.
	v1b := v1
	v1b.Severity = database.HighSeverity
	v1b.FixedIn = []database.FeatureVersion{
		{
			Feature: f1,
			Version: versionfmt.MinVersion,
		},
		{
			Feature: f2,
			Version: versionfmt.MaxVersion,
		},
	}

	if assert.Nil(t, datastore.insertVulnerability(v1b, false, true)) {
		notification, err = datastore.GetAvailableNotification(time.Second)
		assert.Nil(t, err)
		assert.NotEmpty(t, notification.Name)

		if assert.Nil(t, err) && assert.NotEmpty(t, notification.Name) {
			filledNotification, nextPage, err := datastore.GetNotification(notification.Name, 2, database.VulnerabilityNotificationFirstPage)
			if assert.Nil(t, err) {
				if assert.NotNil(t, filledNotification.OldVulnerability) {
					assert.Equal(t, v1.Name, filledNotification.OldVulnerability.Name)
					assert.Equal(t, v1.Severity, filledNotification.OldVulnerability.Severity)
					assert.Len(t, filledNotification.OldVulnerability.LayersIntroducingVulnerability, 2)
				}

				if assert.NotNil(t, filledNotification.NewVulnerability) {
					assert.Equal(t, v1b.Name, filledNotification.NewVulnerability.Name)
					assert.Equal(t, v1b.Severity, filledNotification.NewVulnerability.Severity)
					assert.Len(t, filledNotification.NewVulnerability.LayersIntroducingVulnerability, 1)
				}

				assert.Equal(t, -1, nextPage.NewVulnerability)
			}

			assert.Nil(t, datastore.DeleteNotification(notification.Name))
		}
	}

	// Delete a vulnerability and verify the notification.
	if assert.Nil(t, datastore.DeleteVulnerability(v1b.Namespace.Name, v1b.Name)) {
		notification, err = datastore.GetAvailableNotification(time.Second)
		assert.Nil(t, err)
		assert.NotEmpty(t, notification.Name)

		if assert.Nil(t, err) && assert.NotEmpty(t, notification.Name) {
			filledNotification, _, err := datastore.GetNotification(notification.Name, 2, database.VulnerabilityNotificationFirstPage)
			if assert.Nil(t, err) {
				assert.Nil(t, filledNotification.NewVulnerability)

				if assert.NotNil(t, filledNotification.OldVulnerability) {
					assert.Equal(t, v1b.Name, filledNotification.OldVulnerability.Name)
					assert.Equal(t, v1b.Severity, filledNotification.OldVulnerability.Severity)
					assert.Len(t, filledNotification.OldVulnerability.LayersIntroducingVulnerability, 1)
				}
			}

			assert.Nil(t, datastore.DeleteNotification(notification.Name))
		}
	}
}
