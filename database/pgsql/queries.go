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

const (
	lockVulnerabilityAffects = `LOCK vulnerability_affected_namespaced_feature IN SHARE ROW EXCLUSIVE MODE`

	// keyvalue.go
	searchKeyValue = `SELECT value FROM KeyValue WHERE key = $1`
	upsertKeyValue = `
		INSERT INTO KeyValue(key, value) 
			VALUES ($1, $2) 
			ON CONFLICT ON CONSTRAINT keyvalue_key_key 
			DO UPDATE SET key=$1, value=$2`

	// namespace.go

	searchNamespaceID = `SELECT id FROM Namespace WHERE name = $1 AND version_format = $2`

	// feature.go
	soiNamespacedFeature = `
		WITH new_feature_ns AS (
			INSERT INTO namespaced_feature(feature_id, namespace_id)
			SELECT CAST ($1 AS INTEGER), CAST ($2 AS INTEGER)
			WHERE NOT EXISTS ( SELECT id FROM namespaced_feature WHERE namespaced_feature.feature_id = $1 AND namespaced_feature.namespace_id = $2)
			RETURNING id
		)
		SELECT id FROM namespaced_feature WHERE namespaced_feature.feature_id = $1 AND namespaced_feature.namespace_id = $2
		UNION
		SELECT id FROM new_feature_ns`

	searchPotentialAffectingVulneraibilities = `
		SELECT nf.id, v.id, vaf.affected_version, vaf.id
		FROM vulnerability_affected_feature AS vaf, vulnerability AS v,
			namespaced_feature AS nf, feature AS f
		WHERE nf.id = ANY($1)
			AND nf.feature_id = f.id
			AND nf.namespace_id = v.namespace_id
			AND vaf.feature_name = f.name
			AND vaf.vulnerability_id = v.id
			AND v.deleted_at IS NULL`

	searchNamespacedFeaturesVulnerabilities = `
		SELECT vanf.namespaced_feature_id, v.name, v.description, v.link, 
			v.severity, v.metadata, vaf.fixedin, n.name, n.version_format
		FROM vulnerability_affected_namespaced_feature AS vanf, 
			Vulnerability AS v,
			vulnerability_affected_feature AS vaf,
			namespace AS n
		WHERE vanf.namespaced_feature_id = ANY($1)
			AND vaf.id = vanf.added_by
			AND v.id = vanf.vulnerability_id
			AND n.id = v.namespace_id
			AND v.deleted_at IS NULL`

	// layer.go
	searchLayerIDs = `SELECT id, hash FROM layer WHERE hash = ANY($1);`

	searchLayerFeatures = `
		SELECT feature.Name, feature.Version, feature.version_format 
		FROM feature, layer_feature
		WHERE layer_feature.layer_id = $1
			AND layer_feature.feature_id = feature.id`

	searchLayerNamespaces = `
		SELECT namespace.Name, namespace.version_format 
		FROM namespace, layer_namespace 
		WHERE layer_namespace.layer_id = $1 
			AND layer_namespace.namespace_id = namespace.id`

	searchLayer          = `SELECT id FROM layer WHERE hash = $1`
	searchLayerDetectors = `SELECT detector FROM layer_detector WHERE layer_id = $1`
	searchLayerListers   = `SELECT lister FROM layer_lister WHERE layer_id = $1`

	// lock.go
	soiLock = `INSERT INTO lock(name, owner, until) VALUES ($1, $2, $3)`

	searchLock        = `SELECT owner, until FROM Lock WHERE name = $1`
	updateLock        = `UPDATE Lock SET until = $3 WHERE name = $1 AND owner = $2`
	removeLock        = `DELETE FROM Lock WHERE name = $1 AND owner = $2`
	removeLockExpired = `DELETE FROM LOCK WHERE until < CURRENT_TIMESTAMP`

	// vulnerability.go
	listVulnerabilities = `
		SELECT v.id, v.name, v.description, v.link, v.severity, v.metadata, n.name, n.version_format
		FROM vulnerability AS v, namespace AS n
		WHERE v.namespace_id = n.id
		AND v.deleted_at IS NULL
		`

	searchVulnerability = `
		SELECT v.id, v.description, v.link, v.severity, v.metadata, n.version_format 
		FROM vulnerability AS v, namespace AS n
		WHERE v.namespace_id = n.id
		AND v.name = $1
		AND n.name = $2
		AND v.deleted_at IS NULL
		`

	insertVulnerabilityAffected = `
		INSERT INTO vulnerability_affected_feature(vulnerability_id, feature_name, affected_version, fixedin)
		VALUES ($1, $2, $3, $4)
		RETURNING ID
	`

	searchVulnerabilityAffected = `
		SELECT vulnerability_id, feature_name, affected_version, fixedin 
		FROM vulnerability_affected_feature
		WHERE vulnerability_id = ANY($1)
	`

	searchVulnerabilityByID = `
		SELECT v.name, v.description, v.link, v.severity, v.metadata, n.name, n.version_format
		FROM vulnerability AS v, namespace AS n
		WHERE v.namespace_id = n.id
			AND v.id = $1`

	searchVulnerabilityPotentialAffected = `
		WITH req AS (
			SELECT vaf.id AS vaf_id, n.id AS n_id, vaf.feature_name AS name, v.id AS vulnerability_id
			FROM vulnerability_affected_feature AS vaf,
				vulnerability AS v,
				namespace AS n
			WHERE vaf.vulnerability_id = ANY($1)
			AND v.id = vaf.vulnerability_id
			AND n.id = v.namespace_id
			)
		SELECT req.vulnerability_id, nf.id, f.version, req.vaf_id AS added_by
		FROM feature AS f, namespaced_feature AS nf, req
		WHERE f.name = req.name
		AND nf.namespace_id = req.n_id
		AND nf.feature_id = f.id`

	insertVulnerabilityAffectedNamespacedFeature = `
		INSERT INTO vulnerability_affected_namespaced_feature(vulnerability_id, namespaced_feature_id, added_by)
		VALUES ($1, $2, $3)`

	insertVulnerability = `
		WITH ns AS (
			SELECT id FROM namespace WHERE name = $6 AND version_format = $7
		)
		INSERT INTO Vulnerability(namespace_id, name, description, link, severity, metadata, created_at)
		VALUES((SELECT id FROM ns), $1, $2, $3, $4, $5, CURRENT_TIMESTAMP)
		RETURNING id`

	removeVulnerability = `
		UPDATE Vulnerability
		SET deleted_at = CURRENT_TIMESTAMP
		WHERE namespace_id = (SELECT id FROM Namespace WHERE name = $1)
			AND name = $2
			AND deleted_at IS NULL
		RETURNING id`

	// notification.go
	insertNotification = `
		INSERT INTO Vulnerability_Notification(name, created_at, old_vulnerability_id, new_vulnerability_id)
		VALUES ($1, $2, $3, $4)`

	updatedNotificationNotified = `
		UPDATE Vulnerability_Notification
		SET notified_at = CURRENT_TIMESTAMP
		WHERE name = $1`

	removeNotification = `
		UPDATE Vulnerability_Notification
	  SET deleted_at = CURRENT_TIMESTAMP
	  WHERE name = $1 AND deleted_at IS NULL`

	searchNotificationAvailable = `
		SELECT name, created_at, notified_at, deleted_at
		FROM Vulnerability_Notification
		WHERE (notified_at IS NULL OR notified_at < $1)
					AND deleted_at IS NULL
					AND name NOT IN (SELECT name FROM Lock)
		ORDER BY Random()
		LIMIT 1`

	searchNotification = `
		SELECT created_at, notified_at, deleted_at, old_vulnerability_id, new_vulnerability_id
		FROM Vulnerability_Notification
		WHERE name = $1`

	searchNotificationVulnerableAncestry = `
	   SELECT DISTINCT ON (a.id)
			a.id, a.name
		FROM vulnerability_affected_namespaced_feature AS vanf,
			ancestry AS a, ancestry_feature AS af
		WHERE vanf.vulnerability_id = $1
			AND a.id >= $2
			AND a.id = af.ancestry_id
			AND af.namespaced_feature_id = vanf.namespaced_feature_id
		ORDER BY a.id ASC
		LIMIT $3;`

	// ancestry.go
	persistAncestryLister = `
		INSERT INTO ancestry_lister (ancestry_id, lister)
		SELECT CAST ($1 AS INTEGER), CAST ($2 AS TEXT)
		WHERE NOT EXISTS (SELECT id FROM ancestry_lister WHERE ancestry_id = $1 AND lister = $2) ON CONFLICT DO NOTHING`

	persistAncestryDetector = `
	INSERT INTO ancestry_detector (ancestry_id, detector)
		SELECT CAST ($1 AS INTEGER), CAST ($2 AS TEXT)
		WHERE NOT EXISTS (SELECT id FROM ancestry_detector WHERE ancestry_id = $1 AND detector = $2) ON CONFLICT DO NOTHING`

	insertAncestry = `INSERT INTO ancestry (name) VALUES ($1) RETURNING id`

	searchAncestryLayer = `
		SELECT layer.hash
		FROM layer, ancestry_layer
		WHERE ancestry_layer.ancestry_id = $1
			AND ancestry_layer.layer_id = layer.id
		ORDER BY ancestry_layer.ancestry_index ASC`

	searchAncestryFeatures = `
			SELECT namespace.name, namespace.version_format, feature.name, feature.version 
			FROM namespace, feature, ancestry, namespaced_feature, ancestry_feature
			WHERE ancestry.name = $1
				AND ancestry.id = ancestry_feature.ancestry_id
				AND ancestry_feature.namespaced_feature_id = namespaced_feature.id
				AND namespaced_feature.feature_id = feature.id
				AND namespaced_feature.namespace_id = namespace.id`

	searchAncestry          = `SELECT id FROM ancestry WHERE name = $1`
	searchAncestryDetectors = `SELECT detector FROM ancestry_detector WHERE ancestry_id = $1`
	searchAncestryListers   = `SELECT lister FROM ancestry_lister WHERE ancestry_id = $1`
	removeAncestry          = `DELETE FROM ancestry WHERE name = $1`
	insertAncestryLayer     = `INSERT INTO ancestry_layer(ancestry_id, ancestry_index, layer_id) VALUES($1,$2,$3)`
	insertAncestryFeature   = `INSERT INTO ancestry_feature(ancestry_id, namespaced_feature_id) VALUES ($1, $2)`
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
		SELECT id, name, version, version_format 
		FROM Feature WHERE (name, version, version_format) IN (%s)`,
		queryString(3, featureCount),
	)
}

func querySearchNamespacedFeature(nsfCount int) string {
	return fmt.Sprintf(`
	SELECT nf.id, f.name, f.version, f.version_format, n.name
		FROM namespaced_feature AS nf, feature AS f, namespace AS n
		WHERE nf.feature_id = f.id
			AND nf.namespace_id = n.id
			AND n.version_format = f.version_format 
			AND (f.name, f.version, f.version_format, n.name) IN (%s)`,
		queryString(4, nsfCount),
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
		"feature_name_version_version_format_key",
		"name",
		"version",
		"version_format")
}

func queryPersistLayerFeature(count int) string {
	return queryPersist(count,
		"layer_feature",
		"layer_feature_layer_id_feature_id_key",
		"layer_id",
		"feature_id")
}

func queryPersistNamespace(count int) string {
	return queryPersist(count,
		"namespace",
		"namespace_name_version_format_key",
		"name",
		"version_format")
}

func queryPersistLayerListers(count int) string {
	return queryPersist(count,
		"layer_lister",
		"layer_lister_layer_id_lister_key",
		"layer_id",
		"lister")
}

func queryPersistLayerDetectors(count int) string {
	return queryPersist(count,
		"layer_detector",
		"layer_detector_layer_id_detector_key",
		"layer_id",
		"detector")
}

func queryPersistLayerNamespace(count int) string {
	return queryPersist(count,
		"layer_namespace",
		"layer_namespace_layer_id_namespace_id_key",
		"layer_id",
		"namespace_id")
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
