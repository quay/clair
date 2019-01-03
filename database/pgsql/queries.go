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
	"strings"

	"github.com/lib/pq"
)

// NOTE(Sida): Every search query can only have count less than postgres set
// stack depth. IN will be resolved to nested OR_s and the parser might exceed
// stack depth. TODO(Sida): Generate different queries for different count: if
// count < 5120, use IN; for count > 5120 and < 65536, use temporary table; for
// count > 65535, use is expected to split data into batches.
func querySearchLastDeletedVulnerabilityID(count int) string {
	return fmt.Sprintf(`
			SELECT vid, vname, nname FROM (
				SELECT v.id AS vid, v.name AS vname, n.name AS nname, 
				row_number() OVER (
					PARTITION by (v.name, n.name) 
					ORDER BY v.deleted_at DESC
					) AS rownum 
				FROM vulnerability AS v, namespace AS n 
				WHERE v.namespace_id = n.id 
					AND (v.name, n.name) IN ( %s )
					AND v.deleted_at IS NOT NULL
				) tmp WHERE rownum <= 1`,
		queryString(2, count))
}

func querySearchNotDeletedVulnerabilityID(count int) string {
	return fmt.Sprintf(`
		SELECT v.id, v.name, n.name FROM vulnerability AS v, namespace AS n
		WHERE v.namespace_id = n.id AND (v.name, n.name) IN (%s) 
		AND v.deleted_at IS NULL`,
		queryString(2, count))
}

func querySearchFeatureID(featureCount int) string {
	return fmt.Sprintf(`
		SELECT id, name, version, source_name, source_version, version_format
		FROM Feature WHERE (name, version, version_format) IN (%s)`,
		queryString(3, featureCount),
	)
}

func querySearchNamespacedFeature(nsfCount int) string {
	return fmt.Sprintf(`
	SELECT nf.id, f.name, f.version, f.source_name, f.source_version, f.version_format, n.name
		FROM namespaced_feature AS nf, feature AS f, namespace AS n
		WHERE nf.feature_id = f.id
			AND nf.namespace_id = n.id
			AND n.version_format = f.version_format 
			AND (f.name, f.version, f.source_name, f.source_version,
				f.version_format, n.name) IN (%s)`,
		queryString(6, nsfCount),
	)
}

func querySearchNamespace(nsCount int) string {
	return fmt.Sprintf(
		`SELECT id, name, version_format 
		FROM namespace WHERE (name, version_format) IN (%s)`,
		queryString(2, nsCount),
	)
}

func queryInsert(count int, table string, columns ...string) string {
	base := `INSERT INTO %s (%s) VALUES %s`
	t := pq.QuoteIdentifier(table)
	cols := make([]string, len(columns))
	for i, c := range columns {
		cols[i] = pq.QuoteIdentifier(c)
	}
	colsQuoted := strings.Join(cols, ",")
	return fmt.Sprintf(base, t, colsQuoted, queryString(len(columns), count))
}

func queryPersist(count int, table, constraint string, columns ...string) string {
	ct := ""
	if constraint != "" {
		ct = fmt.Sprintf("ON CONSTRAINT %s", constraint)
	}
	return fmt.Sprintf("%s ON CONFLICT %s DO NOTHING", queryInsert(count, table, columns...), ct)
}

func queryInsertNotifications(count int) string {
	return queryInsert(count,
		"vulnerability_notification",
		"name",
		"created_at",
		"old_vulnerability_id",
		"new_vulnerability_id",
	)
}

func queryPersistFeature(count int) string {
	return queryPersist(count,
		"feature",
		"feature_name_version_source_name_source_version_version_for_key",
		"name",
		"version",
		"source_name",
		"source_version",
		"version_format")
}

func queryPersistLayerFeature(count int) string {
	return queryPersist(count,
		"layer_feature",
		"layer_feature_layer_id_feature_id_key",
		"layer_id",
		"feature_id",
		"detector_id")
}

func queryPersistNamespace(count int) string {
	return queryPersist(count,
		"namespace",
		"namespace_name_version_format_key",
		"name",
		"version_format")
}

func queryPersistLayerNamespace(count int) string {
	return queryPersist(count,
		"layer_namespace",
		"layer_namespace_layer_id_namespace_id_key",
		"layer_id",
		"namespace_id",
		"detector_id")
}

// size of key and array should be both greater than 0
func queryString(keySize, arraySize int) string {
	if arraySize <= 0 || keySize <= 0 {
		panic("Bulk Query requires size of element tuple and number of elements to be greater than 0")
	}
	keys := make([]string, 0, arraySize)
	for i := 0; i < arraySize; i++ {
		key := make([]string, keySize)
		for j := 0; j < keySize; j++ {
			key[j] = fmt.Sprintf("$%d", i*keySize+j+1)
		}
		keys = append(keys, fmt.Sprintf("(%s)", strings.Join(key, ",")))
	}
	return strings.Join(keys, ",")
}

func queryPersistNamespacedFeature(count int) string {
	return queryPersist(count, "namespaced_feature",
		"namespaced_feature_namespace_id_feature_id_key",
		"feature_id",
		"namespace_id")
}

func queryPersistVulnerabilityAffectedNamespacedFeature(count int) string {
	return queryPersist(count, "vulnerability_affected_namespaced_feature",
		"vulnerability_affected_namesp_vulnerability_id_namespaced_f_key",
		"vulnerability_id",
		"namespaced_feature_id",
		"added_by")
}

func queryPersistLayer(count int) string {
	return queryPersist(count, "layer", "", "hash")
}

func queryInvalidateVulnerabilityCache(count int) string {
	return fmt.Sprintf(`DELETE FROM vulnerability_affected_feature 
		WHERE vulnerability_id IN (%s)`,
		queryString(1, count))
}
