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

package namespace

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/database/pgsql/testutil"
)

func TestPersistNamespaces(t *testing.T) {
	tx, cleanup := testutil.CreateTestTx(t, "PersistNamespaces")
	defer cleanup()

	ns1 := database.Namespace{}
	ns2 := database.Namespace{Name: "t", VersionFormat: "b"}

	// Empty Case
	assert.Nil(t, PersistNamespaces(tx, []database.Namespace{}))
	// Invalid Case
	assert.NotNil(t, PersistNamespaces(tx, []database.Namespace{ns1}))
	// Duplicated Case
	assert.Nil(t, PersistNamespaces(tx, []database.Namespace{ns2, ns2}))
	// Existing Case
	assert.Nil(t, PersistNamespaces(tx, []database.Namespace{ns2}))

	nsList := testutil.ListNamespaces(t, tx)
	assert.Len(t, nsList, 1)
	assert.Equal(t, ns2, nsList[0])
}
