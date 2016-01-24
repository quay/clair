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
	"time"

	"github.com/coreos/clair/database"
	cerrors "github.com/coreos/clair/utils/errors"
)

func (pgSQL *pgSQL) insertNamespace(namespace database.Namespace) (int, error) {
	if namespace.Name == "" {
		return 0, cerrors.NewBadRequestError("could not find/insert invalid Namespace")
	}

	if pgSQL.cache != nil {
		promCacheQueriesTotal.WithLabelValues("namespace").Inc()
		if id, found := pgSQL.cache.Get("namespace:" + namespace.Name); found {
			promCacheHitsTotal.WithLabelValues("namespace").Inc()
			return id.(int), nil
		}
	}

	// We do `defer observeQueryTime` here because we don't want to observe cached namespaces.
	defer observeQueryTime("insertNamespace", "all", time.Now())

	var id int
	err := pgSQL.QueryRow(getQuery("soi_namespace"), namespace.Name).Scan(&id)
	if err != nil {
		return 0, handleError("soi_namespace", err)
	}

	if pgSQL.cache != nil {
		pgSQL.cache.Add("namespace:"+namespace.Name, id)
	}

	return id, nil
}
