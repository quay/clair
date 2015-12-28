package pgsql

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestKeyValue(t *testing.T) {
	datastore, err := OpenForTest("KeyValue", false)
	if err != nil {
		t.Error(err)
		return
	}
	defer datastore.Close()

	// Get non-existing key/value
	f, err := datastore.GetKeyValue("test")
	assert.Nil(t, err)
	assert.Empty(t, "", f)

	// Try to insert invalid key/value.
	assert.Error(t, datastore.InsertKeyValue("test", ""))
	assert.Error(t, datastore.InsertKeyValue("", "test"))
	assert.Error(t, datastore.InsertKeyValue("", ""))

	// Insert and verify.
	assert.Nil(t, datastore.InsertKeyValue("test", "test1"))
	f, err = datastore.GetKeyValue("test")
	assert.Nil(t, err)
	assert.Equal(t, "test1", f)

	// Update and verify.
	assert.Nil(t, datastore.InsertKeyValue("test", "test2"))
	f, err = datastore.GetKeyValue("test")
	assert.Nil(t, err)
	assert.Equal(t, "test2", f)
}
