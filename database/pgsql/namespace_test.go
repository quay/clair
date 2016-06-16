// Copyright 2015 clair authors
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

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/utils/types"
	"github.com/stretchr/testify/assert"
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
	id1, err := datastore.insertNamespace(database.Namespace{Name: "TestInsertNamespace", Version: types.NewVersionUnsafe("1")})
	assert.Nil(t, err)
	id2, err := datastore.insertNamespace(database.Namespace{Name: "TestInsertNamespace", Version: types.NewVersionUnsafe("1")})
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
		testDebian7 := database.Namespace{Name: "debian", Version: types.NewVersionUnsafe("7")}
		testDebian8 := database.Namespace{Name: "debian", Version: types.NewVersionUnsafe("8")}
		for _, namespace := range namespaces {
			if namespace.Equal(testDebian7) || namespace.Equal(testDebian8) {
				continue
			} else {
				assert.Error(t, fmt.Errorf("ListNamespaces should not have returned '%s:%s'", namespace.Name, namespace.Version.String()))
			}
		}
	}
}
