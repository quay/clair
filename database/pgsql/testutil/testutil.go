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

package testutil

import (
	"database/sql"
	"fmt"
	"math/rand"
	"testing"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/database/pgsql/page"
	"github.com/coreos/clair/pkg/pagination"
)

func takeVulnerabilityPointerFromMap(m map[int]database.Vulnerability, id int) *database.Vulnerability {
	x := m[id]
	return &x
}

func TakeAncestryPointerFromMap(m map[int]database.Ancestry, id int) *database.Ancestry {
	x := m[id]
	return &x
}

func TakeLayerPointerFromMap(m map[int]database.Layer, id int) *database.Layer {
	x := m[id]
	return &x
}

func ListNamespaces(t *testing.T, tx *sql.Tx) []database.Namespace {
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

func mustUnmarshalToken(key pagination.Key, token pagination.Token) page.Page {
	if token == pagination.FirstPageToken {
		return page.Page{}
	}

	p := page.Page{}
	if err := key.UnmarshalToken(token, &p); err != nil {
		panic(err)
	}

	return p
}

func MustMarshalToken(key pagination.Key, v interface{}) pagination.Token {
	token, err := key.MarshalToken(v)
	if err != nil {
		panic(err)
	}

	return token
}

func GenRandomNamespaces(t *testing.T, count int) []database.Namespace {
	r := make([]database.Namespace, count)
	for i := 0; i < count; i++ {
		r[i] = database.Namespace{
			Name:          fmt.Sprint(rand.Int()),
			VersionFormat: "dpkg",
		}
	}
	return r
}
