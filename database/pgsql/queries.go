package pgsql

import "fmt"

var queries map[string]string

func init() {
	queries = make(map[string]string)

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

	// feature.go
	queries["soi_feature"] = `
    WITH new_feature AS (
      INSERT INTO Feature(name, namespace_id)
      SELECT CAST($1 AS VARCHAR), CAST($2 AS VARCHAR)
      WHERE NOT EXISTS (SELECT id FROM Feature WHERE name = $1 AND namespace_id = $2)
      RETURNING id
    )
    SELECT id FROM Feature WHERE name = $1 AND namespace_id = $2
    UNION
    SELECT id FROM new_feature`

	queries["l_share_vulnerability_fixedin_feature"] = `LOCK Vulnerability_FixedIn_Feature IN SHARE MODE`

	queries["soi_featureversion"] = `
    WITH new_featureversion AS (
      INSERT INTO FeatureVersion(feature_id, version)
      SELECT CAST($1 AS VARCHAR), CAST($2 AS VARCHAR)
      WHERE NOT EXISTS (SELECT id FROM Feature WHERE feature_id = $1 AND version = $2)
      RETURNING id
    )
    SELECT 'exi', id FROM Feature WHERE feature_id = $1 AND version = $2
    UNION
    SELECT 'new', id FROM new_featureversion
  `

	queries["s_vulnerability_fixedin_feature"] = `
    SELECT id, vulnerability_id, version FROM Vulnerability_FixedIn_Feature
    WHERE feature_id = ?`

	queries["i_vulnerability_affects_featureversion"] = `
    INSERT INTO Vulnerability_Affects_FeatureVersion(vulnerability_id,
    featureversion_id, fixedin_id) VALUES($1, $2, $3)`

	// layer.go
	queries["s_layer"] = `
    SELECT l.id, l.name, l.engineversion, p.name, n.name
    FROM Layer l
      LEFT JOIN Layer p ON l.parent_id = p.id
      LEFT JOIN Namespace n ON l.namespace_id = n.id
    WHERE l.name = $1;`

	queries["s_layer_featureversion_id_only"] = `
    WITH RECURSIVE layer_tree(id, parent_id, depth, path, cycle) AS(
      SELECT l.id, l.parent_id, 1, ARRAY[l.id], false
      FROM Layer l
      WHERE l.id = $1
    UNION ALL
      SELECT l.id, l.parent_id, lt.depth + 1, path || l.id, l.id = ANY(path)
      FROM Layer l, layer_tree lt
      WHERE l.id = lt.parent_id
    )
    SELECT ldf.featureversion_id, ldf.modification
    FROM Layer_diff_FeatureVersion ldf
    JOIN (
      SELECT row_number() over (ORDER BY depth DESC), id FROM layer_tree
    ) AS ltree (ordering, id) ON ldf.layer_id = ltree.id
    ORDER BY ltree.ordering`

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
    SELECT vafv.featureversion_id, v.id, v.name, v.description, v.link, v.severity, vn.name, vfif.version
    FROM Vulnerability_Affects_FeatureVersion vafv, Vulnerability v,
         Namespace vn, Vulnerability_FixedIn_Feature vfif
    WHERE vafv.featureversion_id = ANY($1::integer[])
          AND vafv.vulnerability_id = v.id
          AND vafv.fixedin_id = vfif.id
          AND v.namespace_id = vn.id`

	queries["i_layer"] = `INSERT INTO Layer(name, engine_version, parent_id, namespace_id) VALUES($1, $2, $3, $4) RETURNING id`

	queries["u_layer"] = `UPDATE LAYER SET engine_version = $2, namespace_id = $3) WHERE id = $1`
}

func getQuery(name string) string {
	if query, ok := queries[name]; ok {
		return query
	}
	panic(fmt.Sprintf("pgsql: unknown query %v", name))
}
