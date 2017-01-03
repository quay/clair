// Copyright 2016 clair authors
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
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/ext/versionfmt/dpkg"
)

func TestInsertNamespace(t *testing.T) {
	datastore, err := openDatabaseForTest("InsertNamespace", false)
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
	id1, err := datastore.insertNamespace(database.Namespace{
		Name:          "TestInsertNamespace1",
		VersionFormat: dpkg.ParserName,
	})
	assert.Nil(t, err)
	id2, err := datastore.insertNamespace(database.Namespace{
		Name:          "TestInsertNamespace1",
		VersionFormat: dpkg.ParserName,
	})
	assert.Nil(t, err)
	assert.Equal(t, id1, id2)
}

func TestListNamespace(t *testing.T) {
	datastore, err := openDatabaseForTest("ListNamespaces", true)
	if err != nil {
		t.Error(err)
		return
	}
	defer datastore.Close()

	namespaces, err := datastore.ListNamespaces()
	assert.Nil(t, err)
	if assert.Len(t, namespaces, 2) {
		for _, namespace := range namespaces {
			switch namespace.Name {
			case "debian:7", "debian:8":
				continue
			default:
				assert.Error(t, fmt.Errorf("ListNamespaces should not have returned '%s'", namespace.Name))
			}
		}
	}
}
