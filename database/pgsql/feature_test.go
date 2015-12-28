package pgsql

import (
	"testing"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/utils/types"
	"github.com/stretchr/testify/assert"
)

func TestInsertFeature(t *testing.T) {
	datastore, err := OpenForTest("InsertFeature", false)
	if err != nil {
		t.Error(err)
		return
	}
	defer datastore.Close()

	// Invalid Feature.
	id0, err := datastore.insertFeature(database.Feature{})
	assert.NotNil(t, err)
	assert.Zero(t, id0)

	id0, err = datastore.insertFeature(database.Feature{
		Namespace: database.Namespace{},
		Name:      "TestInsertFeature0",
	})
	assert.NotNil(t, err)
	assert.Zero(t, id0)

	// Insert Feature and ensure we can find it.
	feature := database.Feature{
		Namespace: database.Namespace{Name: "TestInsertFeatureNamespace1"},
		Name:      "TestInsertFeature1",
	}
	id1, err := datastore.insertFeature(feature)
	assert.Nil(t, err)
	id2, err := datastore.insertFeature(feature)
	assert.Nil(t, err)
	assert.Equal(t, id1, id2)

	// Insert invalid FeatureVersion.
	for _, invalidFeatureVersion := range []database.FeatureVersion{
		database.FeatureVersion{
			Feature: database.Feature{},
			Version: types.NewVersionUnsafe("1.0"),
		},
		database.FeatureVersion{
			Feature: database.Feature{
				Namespace: database.Namespace{},
				Name:      "TestInsertFeature2",
			},
			Version: types.NewVersionUnsafe("1.0"),
		},
		database.FeatureVersion{
			Feature: database.Feature{
				Namespace: database.Namespace{Name: "TestInsertFeatureNamespace2"},
				Name:      "TestInsertFeature2",
			},
			Version: types.NewVersionUnsafe(""),
		},
		database.FeatureVersion{
			Feature: database.Feature{
				Namespace: database.Namespace{Name: "TestInsertFeatureNamespace2"},
				Name:      "TestInsertFeature2",
			},
			Version: types.NewVersionUnsafe("bad version"),
		},
	} {
		id3, err := datastore.insertFeatureVersion(invalidFeatureVersion)
		assert.Error(t, err)
		assert.Zero(t, id3)
	}

	// Insert FeatureVersion and ensure we can find it.
	featureVersion := database.FeatureVersion{
		Feature: database.Feature{
			Namespace: database.Namespace{Name: "TestInsertFeatureNamespace1"},
			Name:      "TestInsertFeature1",
		},
		Version: types.NewVersionUnsafe("2:3.0-imba"),
	}
	id4, err := datastore.insertFeatureVersion(featureVersion)
	assert.Nil(t, err)
	id5, err := datastore.insertFeatureVersion(featureVersion)
	assert.Nil(t, err)
	assert.Equal(t, id4, id5)
}
