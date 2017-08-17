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
	"database/sql"
	"errors"
	"sort"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/pkg/commonerr"
)

var (
	errNamespaceNotFound = errors.New("Requested Namespace is not in database")
)

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

func (tx *pgSession) findNamespaceIDs(namespaces []database.Namespace) ([]sql.NullInt64, error) {
	if len(namespaces) == 0 {
		return nil, nil
	}

	keys := make([]interface{}, len(namespaces)*2)
	nsMap := map[database.Namespace]sql.NullInt64{}
	for i, n := range namespaces {
		keys[i*2] = n.Name
		keys[i*2+1] = n.VersionFormat
		nsMap[n] = sql.NullInt64{}
	}

	rows, err := tx.Query(querySearchNamespace(len(namespaces)), keys...)
	if err != nil {
		return nil, handleError("searchNamespace", err)
	}

	defer rows.Close()

	var (
		id sql.NullInt64
		ns database.Namespace
	)
	for rows.Next() {
		err := rows.Scan(&id, &ns.Name, &ns.VersionFormat)
		if err != nil {
			return nil, handleError("searchNamespace", err)
		}
		nsMap[ns] = id
	}

	ids := make([]sql.NullInt64, len(namespaces))
	for i, ns := range namespaces {
		ids[i] = nsMap[ns]
	}

	return ids, nil
}
