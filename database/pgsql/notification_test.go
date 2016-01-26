package pgsql

import (
	"testing"
	"time"

	"fmt"

	"github.com/coreos/clair/database"
	cerrors "github.com/coreos/clair/utils/errors"
	"github.com/coreos/clair/utils/types"
	"github.com/stretchr/testify/assert"
)

func TestNotification(t *testing.T) {
	datastore, err := OpenForTest("Notification", false)
	if err != nil {
		t.Error(err)
		return
	}
	defer datastore.Close()

	// Try to get a notification when there is none.
	_, err = datastore.GetAvailableNotification(time.Second)
	assert.Equal(t, cerrors.ErrNotFound, err)

	// Create some data.
	f1 := database.Feature{
		Name:      "TestNotificationFeature1",
		Namespace: database.Namespace{Name: "TestNotificationNamespace1"},
	}

	l1 := database.Layer{
		Name: "TestNotificationLayer1",
		Features: []database.FeatureVersion{
			database.FeatureVersion{
				Feature: f1,
				Version: types.NewVersionUnsafe("0.1"),
			},
		},
	}

	l2 := database.Layer{
		Name: "TestNotificationLayer2",
		Features: []database.FeatureVersion{
			database.FeatureVersion{
				Feature: f1,
				Version: types.NewVersionUnsafe("0.2"),
			},
		},
	}

	l3 := database.Layer{
		Name: "TestNotificationLayer3",
		Features: []database.FeatureVersion{
			database.FeatureVersion{
				Feature: f1,
				Version: types.NewVersionUnsafe("0.3"),
			},
		},
	}

	if assert.Nil(t, datastore.InsertLayer(l1)) && assert.Nil(t, datastore.InsertLayer(l2)) &&
		assert.Nil(t, datastore.InsertLayer(l3)) {

		// Insert a new vulnerability that is introduced by three layers.
		v1 := database.Vulnerability{
			Name:        "TestNotificationVulnerability1",
			Namespace:   f1.Namespace,
			Description: "TestNotificationDescription1",
			Link:        "TestNotificationLink1",
			Severity:    "Unknown",
			FixedIn: []database.FeatureVersion{
				database.FeatureVersion{
					Feature: f1,
					Version: types.NewVersionUnsafe("1.0"),
				},
			},
		}
		assert.Nil(t, datastore.insertVulnerability(v1))

		// Get the notification associated to the previously inserted vulnerability.
		notification, err := datastore.GetAvailableNotification(time.Second)
		assert.Nil(t, err)
		assert.NotEmpty(t, notification.Name)

		// Verify the renotify behaviour.
		if assert.Nil(t, datastore.SetNotificationNotified(notification.Name)) {
			_, err := datastore.GetAvailableNotification(time.Second)
			assert.Equal(t, cerrors.ErrNotFound, err)

			time.Sleep(50 * time.Millisecond)
			notificationB, err := datastore.GetAvailableNotification(20 * time.Millisecond)
			assert.Nil(t, err)
			assert.Equal(t, notification.Name, notificationB.Name)

			datastore.SetNotificationNotified(notification.Name)
		}

		// Get notification.
		filledNotification, nextPage, err := datastore.GetNotification(notification.Name, 2, database.VulnerabilityNotificationFirstPage)
		assert.Nil(t, err)
		assert.NotEqual(t, database.NoVulnerabilityNotificationPage, nextPage)
		assert.Nil(t, filledNotification.OldVulnerability)
		assert.Equal(t, v1.Name, filledNotification.NewVulnerability.Name)
		assert.Len(t, filledNotification.NewVulnerability.LayersIntroducingVulnerability, 2)

		// Get second page.
		filledNotification, nextPage, err = datastore.GetNotification(notification.Name, 2, nextPage)
		assert.Nil(t, err)
		assert.Equal(t, database.NoVulnerabilityNotificationPage, nextPage)
		assert.Nil(t, filledNotification.OldVulnerability)
		assert.Equal(t, v1.Name, filledNotification.NewVulnerability.Name)
		assert.Len(t, filledNotification.NewVulnerability.LayersIntroducingVulnerability, 1)

		// Delete notification.
		assert.Nil(t, datastore.DeleteNotification(notification.Name))

		n, err := datastore.GetAvailableNotification(time.Millisecond)
		assert.Equal(t, cerrors.ErrNotFound, err)
		fmt.Println(n)
	}
}
