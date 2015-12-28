package pgsql

import (
	"testing"

	"github.com/coreos/clair/database"
	"github.com/stretchr/testify/assert"
)

func TestInsertNamespace(t *testing.T) {
	datastore, err := OpenForTest("InsertNamespace", false)
	if err != nil {
		t.Error(err)
		return
	}
	defer datastore.Close()

	// Invalid Namespace.
	id0, err := datastore.insertNamespace(database.Namespace{})
	assert.NotNil(t, err)
	assert.Zero(t, id0)

	// Insert Namespace and ensure we can find it.
	id1, err := datastore.insertNamespace(database.Namespace{Name: "TestInsertNamespace1"})
	assert.Nil(t, err)
	id2, err := datastore.insertNamespace(database.Namespace{Name: "TestInsertNamespace1"})
	assert.Nil(t, err)
	assert.Equal(t, id1, id2)
}
