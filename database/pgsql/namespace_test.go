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
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/coreos/clair/database"
)

func TestPersistNamespaces(t *testing.T) {
	datastore, tx := openSessionForTest(t, "PersistNamespaces", false)
	defer closeTest(t, datastore, tx)

	ns1 := database.Namespace{}
	ns2 := database.Namespace{Name: "t", VersionFormat: "b"}

	// Empty Case
	assert.Nil(t, tx.PersistNamespaces([]database.Namespace{}))
	// Invalid Case
	assert.NotNil(t, tx.PersistNamespaces([]database.Namespace{ns1}))
	// Duplicated Case
	assert.Nil(t, tx.PersistNamespaces([]database.Namespace{ns2, ns2}))
	// Existing Case
	assert.Nil(t, tx.PersistNamespaces([]database.Namespace{ns2}))

	nsList := listNamespaces(t, tx)
	assert.Len(t, nsList, 1)
	assert.Equal(t, ns2, nsList[0])
}

func assertNamespacesEqual(t *testing.T, expected []database.Namespace, actual []database.Namespace) bool {
	if assert.Len(t, actual, len(expected)) {
		has := map[database.Namespace]bool{}
		for _, i := range expected {
			has[i] = false
		}
		for _, i := range actual {
			has[i] = true
		}
		for key, v := range has {
			if !assert.True(t, v, key.Name+"is expected") {
				return false
			}
		}
		return true
	}
	return false
}

func listNamespaces(t *testing.T, tx *pgSession) []database.Namespace {
	rows, err := tx.Query("SELECT name, version_format FROM namespace")
	if err != nil {
		t.FailNow()
	}
	defer rows.Close()

	namespaces := []database.Namespace{}
	for rows.Next() {
		var ns database.Namespace
		err := rows.Scan(&ns.Name, &ns.VersionFormat)
		if err != nil {
			t.FailNow()
		}
		namespaces = append(namespaces, ns)
	}

	return namespaces
}
