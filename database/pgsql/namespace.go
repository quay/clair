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
	"sort"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/pkg/commonerr"
)

const (
	searchNamespaceID = `SELECT id FROM Namespace WHERE name = $1 AND version_format = $2`
)

type namespaceMap struct {
	byID    map[int]database.Namespace
	byValue map[database.Namespace]int
}

func newNamespaceMap() namespaceMap {
	return namespaceMap{make(map[int]database.Namespace), make(map[database.Namespace]int)}
}

func (m *namespaceMap) ContainValue(namespace database.Namespace) bool {
	_, ok := m.byValue[namespace]
	return ok
}

func (m *namespaceMap) Add(id int, namespace database.Namespace) {
	m.byID[id] = namespace
	m.byValue[namespace] = id
}

// PersistNamespaces soi namespaces into database.
func (tx *pgSession) PersistNamespaces(namespaces []database.Namespace) error {
	if len(namespaces) == 0 {
		return nil
	}

	// Sorting is needed before inserting into database to prevent deadlock.
	sort.Slice(namespaces, func(i, j int) bool {
		return namespaces[i].Name < namespaces[j].Name &&
			namespaces[i].VersionFormat < namespaces[j].VersionFormat
	})

	keys := make([]interface{}, len(namespaces)*2)
	for i, ns := range namespaces {
		if ns.Name == "" || ns.VersionFormat == "" {
			return commonerr.NewBadRequestError("Empty namespace name or version format is not allowed")
		}
		keys[i*2] = ns.Name
		keys[i*2+1] = ns.VersionFormat
	}

	_, err := tx.Exec(queryPersistNamespace(len(namespaces)), keys...)
	if err != nil {
		return handleError("queryPersistNamespace", err)
	}
	return nil
}

// searchNamespaces searches the ID for all the namespaces in the input.
func (tx *pgSession) searchNamespaces(namespaces []database.Namespace) (namespaceMap, error) {
	m := newNamespaceMap()
	if len(namespaces) == 0 {
		return m, nil
	}

	namespaces = database.DeduplicateNamespaces(namespaces...)
	keys := make([]interface{}, len(namespaces)*2)
	for i, n := range namespaces {
		keys[i*2] = n.Name
		keys[i*2+1] = n.VersionFormat
	}

	rows, err := tx.Query(querySearchNamespaces(len(namespaces)), keys...)
	if err != nil {
		return m, handleError("searchNamespaces", err)
	}

	defer rows.Close()

	for rows.Next() {
		var (
			id int
			ns database.Namespace
		)

		if err := rows.Scan(&id, &ns.Name, &ns.VersionFormat); err != nil {
			return m, handleError("searchNamespaces", err)
		}

		m.Add(id, ns)
	}

	// ensure that all namespaces exist in the map, otherwise, return missing entities
	for _, n := range namespaces {
		if !m.ContainValue(n) {
			return m, database.ErrMissingEntities
		}
	}

	return m, nil
}
