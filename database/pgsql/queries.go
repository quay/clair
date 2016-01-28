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
	"strconv"
)

var queries map[string]string

func init() {
	queries = make(map[string]string)

	queries["l_vulnerability_affects_featureversion"] = `LOCK Vulnerability_Affects_FeatureVersion IN SHARE ROW EXCLUSIVE MODE`

	// keyvalue.go
	queries["u_keyvalue"] = `UPDATE KeyValue SET value = $1 WHERE key = $2`
	queries["i_keyvalue"] = `INSERT INTO KeyValue(key, value) VALUES($1, $2)`
	queries["s_keyvalue"] = `SELECT value FROM KeyValue WHERE key = $1`

	// namespace.go
	queries["soi_namespace"] = `
    WITH new_namespace AS (
      INSERT INTO Namespace(name)
      SELECT CAST($1 AS VARCHAR)
      WHERE NOT EXISTS (SELECT name FROM Namespace WHERE name = $1)
      RETURNING id
    )
    SELECT id FROM Namespace WHERE name = $1
    UNION
    SELECT id FROM new_namespace`

	queries["l_namespace"] = `SELECT id, name FROM Namespace`

	// feature.go
	queries["soi_feature"] = `
    WITH new_feature AS (
      INSERT INTO Feature(name, namespace_id)
      SELECT CAST($1 AS VARCHAR), CAST($2 AS INTEGER)
      WHERE NOT EXISTS (SELECT id FROM Feature WHERE name = $1 AND namespace_id = $2)
      RETURNING id
    )
    SELECT id FROM Feature WHERE name = $1 AND namespace_id = $2
    UNION
    SELECT id FROM new_feature`

	queries["soi_featureversion"] = `
    WITH new_featureversion AS (
      INSERT INTO FeatureVersion(feature_id, version)
      SELECT CAST($1 AS INTEGER), CAST($2 AS VARCHAR)
      WHERE NOT EXISTS (SELECT id FROM FeatureVersion WHERE feature_id = $1 AND version = $2)
      RETURNING id
    )
    SELECT 'exi', id FROM FeatureVersion WHERE feature_id = $1 AND version = $2
    UNION
    SELECT 'new', id FROM new_featureversion
  `

	queries["s_vulnerability_fixedin_feature"] = `
    SELECT id, vulnerability_id, version FROM Vulnerability_FixedIn_Feature
    WHERE feature_id = $1`

	queries["i_vulnerability_affects_featureversion"] = `
    INSERT INTO Vulnerability_Affects_FeatureVersion(vulnerability_id,
    featureversion_id, fixedin_id) VALUES($1, $2, $3)`

	// layer.go
	queries["s_layer"] = `
    SELECT l.id, l.name, l.engineversion, p.id, p.name, n.id, n.name
    FROM Layer l
      LEFT JOIN Layer p ON l.parent_id = p.id
      LEFT JOIN Namespace n ON l.namespace_id = n.id
    WHERE l.name = $1;`

	queries["s_layer_featureversion"] = `
    WITH RECURSIVE layer_tree(id, parent_id, depth, path, cycle) AS(
      SELECT l.id, l.parent_id, 1, ARRAY[l.id], false
      FROM Layer l
      WHERE l.id = $1
    UNION ALL
      SELECT l.id, l.parent_id, lt.depth + 1, path || l.id, l.id = ANY(path)
      FROM Layer l, layer_tree lt
      WHERE l.id = lt.parent_id
    )
    SELECT ldf.featureversion_id, ldf.modification, fn.id, fn.name, f.id, f.name, fv.id, fv.version
    FROM Layer_diff_FeatureVersion ldf
    JOIN (
      SELECT row_number() over (ORDER BY depth DESC), id FROM layer_tree
    ) AS ltree (ordering, id) ON ldf.layer_id = ltree.id, FeatureVersion fv, Feature f, Namespace fn
    WHERE ldf.featureversion_id = fv.id AND fv.feature_id = f.id AND f.namespace_id = fn.id
    ORDER BY ltree.ordering`

	queries["s_featureversions_vulnerabilities"] = `
    SELECT vafv.featureversion_id, v.id, v.name, v.description, v.link, v.severity, vn.name,
      vfif.version
    FROM Vulnerability_Affects_FeatureVersion vafv, Vulnerability v,
         Namespace vn, Vulnerability_FixedIn_Feature vfif
    WHERE vafv.featureversion_id = ANY($1::integer[])
          AND vafv.vulnerability_id = v.id
          AND vafv.fixedin_id = vfif.id
          AND v.namespace_id = vn.id`

	queries["i_layer"] = `
    INSERT INTO Layer(name, engineversion, parent_id, namespace_id)
    VALUES($1, $2, $3, $4) RETURNING id`

	queries["u_layer"] = `UPDATE LAYER SET engineversion = $2, namespace_id = $3 WHERE id = $1`

	queries["r_layer_diff_featureversion"] = `
    DELETE FROM Layer_diff_FeatureVersion
    WHERE layer_id = $1`

	queries["i_layer_diff_featureversion"] = `
    INSERT INTO Layer_diff_FeatureVersion(layer_id, featureversion_id, modification)
      SELECT $1, fv.id, $2
	    FROM FeatureVersion fv
	    WHERE fv.id = ANY($3::integer[])`

	queries["r_layer"] = `DELETE FROM Layer WHERE name = $1`

	// lock.go
	queries["i_lock"] = `INSERT INTO Lock(name, owner, until) VALUES($1, $2, $3)`

	queries["f_lock"] = `SELECT owner, until FROM Lock WHERE name = $1`

	queries["u_lock"] = `UPDATE Lock SET until = $3 WHERE name = $1 AND owner = $2`

	queries["r_lock"] = `DELETE FROM Lock WHERE name = $1 AND owner = $2`

	queries["r_lock_expired"] = `DELETE FROM LOCK WHERE until < CURRENT_TIMESTAMP`

	// vulnerability.go
	queries["f_vulnerability"] = `
    SELECT v.id, n.id, v.description, v.link, v.severity, vfif.version, f.id, f.Name
    FROM Vulnerability v
      JOIN Namespace n ON v.namespace_id = n.id
      LEFT JOIN Vulnerability_FixedIn_Feature vfif ON v.id = vfif.vulnerability_id
      LEFT JOIN Feature f ON vfif.feature_id = f.id
    WHERE n.Name = $1 AND v.Name = $2`

	queries["i_vulnerability"] = `
    INSERT INTO Vulnerability(namespace_id, name, description, link, severity)
    VALUES($1, $2, $3, $4, $5)
    RETURNING id`

	queries["u_vulnerability"] = `
    UPDATE Vulnerability SET description = $2, link = $3, severity = $4 WHERE id = $1`

	queries["i_vulnerability_fixedin_feature"] = `
    INSERT INTO Vulnerability_FixedIn_Feature(vulnerability_id, feature_id, version)
    VALUES($1, $2, $3)
    RETURNING id`

	queries["u_vulnerability_fixedin_feature"] = `
    UPDATE Vulnerability_FixedIn_Feature
    SET version = $3
    WHERE vulnerability_id = $1 AND feature_id = $2
    RETURNING id`

	queries["r_vulnerability_fixedin_feature"] = `
    DELETE FROM Vulnerability_FixedIn_Feature
    WHERE vulnerability_id = $1 AND feature_id = $2
    RETURNING id`

	queries["r_vulnerability_affects_featureversion"] = `
    DELETE FROM Vulnerability_Affects_FeatureVersion
    WHERE fixedin_id = $1`

	queries["f_featureversion_by_feature"] = `
    SELECT id, version FROM FeatureVersion WHERE feature_id = $1`

	queries["r_vulnerability"] = `
    DELETE FROM Vulnerability
    WHERE namespace_id = (SELECT id FROM Namespace WHERE name = $1)
          AND name = $2`

	// notification.go
	queries["i_notification"] = `
    INSERT INTO Vulnerability_Notification(name, created_at, old_vulnerability, new_vulnerability)
    VALUES($1, CURRENT_TIMESTAMP, $2, $3)`

	queries["u_notification_notified"] = `
    UPDATE Vulnerability_Notification
    SET notified_at = CURRENT_TIMESTAMP
    WHERE name = $1`

	queries["r_notification"] = `
    UPDATE Vulnerability_Notification
    SET deleted_at = CURRENT_TIMESTAMP
    WHERE name = $1`

	queries["s_notification_available"] = `
    SELECT id, name, created_at, notified_at, deleted_at
    FROM Vulnerability_Notification
    WHERE (notified_at IS NULL OR notified_at < $1)
          AND deleted_at IS NULL
          AND name NOT IN (SELECT name FROM Lock)
    ORDER BY Random()
    LIMIT 1`

	queries["s_notification"] = `
    SELECT id, name, created_at, notified_at, deleted_at, old_vulnerability, new_vulnerability
    FROM Vulnerability_Notification
    WHERE name = $1`

	queries["s_notification_layer_introducing_vulnerability"] = `
    SELECT l.ID, l.name
    FROM Vulnerability v, Vulnerability_Affects_FeatureVersion vafv, FeatureVersion fv, Layer_diff_FeatureVersion ldfv, Layer l
    WHERE v.id = $1
          AND v.id = vafv.vulnerability_id
          AND vafv.featureversion_id = fv.id
          AND fv.id = ldfv.featureversion_id
          AND ldfv.modification = 'add'
          AND ldfv.layer_id = l.id
          AND l.id >= $2
    ORDER BY l.ID
    LIMIT $3`

	// complex_test.go
	queries["s_complextest_featureversion_affects"] = `
    SELECT v.name
    FROM FeatureVersion fv
      LEFT JOIN Vulnerability_Affects_FeatureVersion vaf ON fv.id = vaf.featureversion_id
      JOIN Vulnerability v ON vaf.vulnerability_id = v.id
    WHERE featureversion_id = $1`
}

func getQuery(name string) string {
	if query, ok := queries[name]; ok {
		return query
	}
	panic(fmt.Sprintf("pgsql: unknown query %v", name))
}

// buildInputArray constructs a PostgreSQL input array from the specified integers.
// Useful to use the `= ANY($1::integer[])` syntax that let us use a IN clause while using
// a single placeholder.
func buildInputArray(ints []int) string {
	str := "{"
	for i := 0; i < len(ints)-1; i++ {
		str = str + strconv.Itoa(ints[i]) + ","
	}
	str = str + strconv.Itoa(ints[len(ints)-1]) + "}"
	return str
}
