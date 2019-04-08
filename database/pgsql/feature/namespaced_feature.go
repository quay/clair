// Copyright 2019 clair authors
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

package feature

import (
	"database/sql"
	"fmt"
	"sort"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/database/pgsql/namespace"
	"github.com/coreos/clair/database/pgsql/util"
)

var soiNamespacedFeature = `
WITH new_feature_ns AS (
	INSERT INTO namespaced_feature(feature_id, namespace_id)
	SELECT CAST ($1 AS INTEGER), CAST ($2 AS INTEGER)
	WHERE NOT EXISTS ( SELECT id FROM namespaced_feature WHERE namespaced_feature.feature_id = $1 AND namespaced_feature.namespace_id = $2)
	RETURNING id
)
SELECT id FROM namespaced_feature WHERE namespaced_feature.feature_id = $1 AND namespaced_feature.namespace_id = $2
UNION
SELECT id FROM new_feature_ns`

func queryPersistNamespacedFeature(count int) string {
	return util.QueryPersist(count, "namespaced_feature",
		"namespaced_feature_namespace_id_feature_id_key",
		"feature_id",
		"namespace_id")
}

func querySearchNamespacedFeature(nsfCount int) string {
	return fmt.Sprintf(`
	SELECT nf.id, f.name, f.version, f.version_format, t.name, n.name
		FROM namespaced_feature AS nf, feature AS f, namespace AS n, feature_type AS t
		WHERE nf.feature_id = f.id
			AND nf.namespace_id = n.id
			AND n.version_format = f.version_format 
			AND f.type = t.id
			AND (f.name, f.version, f.version_format, t.name, n.name) IN (%s)`,
		util.QueryString(5, nsfCount),
	)
}

type namespacedFeatureWithID struct {
	database.NamespacedFeature

	ID int64
}

func PersistNamespacedFeatures(tx *sql.Tx, features []database.NamespacedFeature) error {
	if len(features) == 0 {
		return nil
	}

	nsIDs := map[database.Namespace]sql.NullInt64{}
	fIDs := map[database.Feature]sql.NullInt64{}
	for _, f := range features {
		nsIDs[f.Namespace] = sql.NullInt64{}
		fIDs[f.Feature] = sql.NullInt64{}
	}

	fToFind := []database.Feature{}
	for f := range fIDs {
		fToFind = append(fToFind, f)
	}

	sort.Slice(fToFind, func(i, j int) bool {
		return fToFind[i].Name < fToFind[j].Name ||
			fToFind[i].Version < fToFind[j].Version ||
			fToFind[i].VersionFormat < fToFind[j].VersionFormat
	})

	if ids, err := FindFeatureIDs(tx, fToFind); err == nil {
		for i, id := range ids {
			if !id.Valid {
				return database.ErrMissingEntities
			}
			fIDs[fToFind[i]] = id
		}
	} else {
		return err
	}

	nsToFind := []database.Namespace{}
	for ns := range nsIDs {
		nsToFind = append(nsToFind, ns)
	}

	if ids, err := namespace.FindNamespaceIDs(tx, nsToFind); err == nil {
		for i, id := range ids {
			if !id.Valid {
				return database.ErrMissingEntities
			}
			nsIDs[nsToFind[i]] = id
		}
	} else {
		return err
	}

	keys := make([]interface{}, 0, len(features)*2)
	for _, f := range features {
		keys = append(keys, fIDs[f.Feature], nsIDs[f.Namespace])
	}

	_, err := tx.Exec(queryPersistNamespacedFeature(len(features)), keys...)
	if err != nil {
		return err
	}

	return nil
}

func FindNamespacedFeatureIDs(tx *sql.Tx, nfs []database.NamespacedFeature) ([]sql.NullInt64, error) {
	if len(nfs) == 0 {
		return nil, nil
	}

	nfsMap := map[database.NamespacedFeature]int64{}
	keys := make([]interface{}, 0, len(nfs)*5)
	for _, nf := range nfs {
		keys = append(keys, nf.Name, nf.Version, nf.VersionFormat, nf.Type, nf.Namespace.Name)
	}

	rows, err := tx.Query(querySearchNamespacedFeature(len(nfs)), keys...)
	if err != nil {
		return nil, util.HandleError("searchNamespacedFeature", err)
	}

	defer rows.Close()
	var (
		id int64
		nf database.NamespacedFeature
	)

	for rows.Next() {
		err := rows.Scan(&id, &nf.Name, &nf.Version, &nf.VersionFormat, &nf.Type, &nf.Namespace.Name)
		nf.Namespace.VersionFormat = nf.VersionFormat
		if err != nil {
			return nil, util.HandleError("searchNamespacedFeature", err)
		}
		nfsMap[nf] = id
	}

	ids := make([]sql.NullInt64, len(nfs))
	for i, nf := range nfs {
		if id, ok := nfsMap[nf]; ok {
			ids[i] = sql.NullInt64{id, true}
		} else {
			ids[i] = sql.NullInt64{}
		}
	}

	return ids, nil
}
