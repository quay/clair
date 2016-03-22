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

package mysql

import "strconv"

const (
	// This is for lock the table
	lockVulnerabilityAffects = `select count(*) from Vulnerability_Affects_FeatureVersion where vulnerability_id > 0 for update`

	// keyvalue.go
	updateKeyValue = "UPDATE KeyValue SET `value` = ? WHERE `key` = ?"
	insertKeyValue = "INSERT INTO KeyValue(`key`, `value`) VALUES(?, ?)"
	searchKeyValue = "SELECT `value` FROM KeyValue WHERE `key` = ?"

	// namespace.go
	insertNamespace = `insert into Namespace(name) select ? from dual where not exists (select * from Namespace where name = ?)`
	soiNamespace    = `SELECT id from Namespace WHERE name = ?`

	listNamespace   = `SELECT id, name FROM Namespace`
	searchNamespace = `SELECT id FROM Namespace WHERE name = ?`

	// feature.go
	insertFeature = `insert into Feature(name, namespace_id) select CAST(? AS CHAR), CAST(? AS UNSIGNED) FROM dual WHERE NOT EXISTS (SELECT id FROM Feature WHERE name = ? AND namespace_id = ?)`
	soiFeature    = `SELECT id FROM Feature WHERE name = ? AND namespace_id = ?`

	insertFeatureVersion = `
		Insert into FeatureVersion(feature_id, version) select cast(? AS unsigned),cast(? as char) from dual where not exists (select * from FeatureVersion where feature_id = ? AND version = ?) LIMIT 1`
	// TODO: need to handle 'exi'
	soiFeatureVersion = `SELECT 'new', id FROM FeatureVersion WHERE feature_id = ? AND version = ?`

	searchFeatureVersion              = `SELECT id FROM FeatureVersion WHERE feature_id = ? AND version = ?`
	searchVulnerabilityFixedInFeature = `
		SELECT id, vulnerability_id, version FROM Vulnerability_FixedIn_Feature  WHERE feature_id = ?`

	insertVulnerabilityAffectsFeatureVersion = `
		INSERT INTO Vulnerability_Affects_FeatureVersion(vulnerability_id, featureversion_id, fixedin_id) select ?,?,? from dual where not exists (select * from Vulnerability_Affects_FeatureVersion where vulnerability_id =? and featureversion_id = ? and fixedin_id = ?)`
	// layer.go
	searchLayer = `
		SELECT l.id, l.name, l.engineversion, p.id, p.name, n.id, n.name
		FROM Layer l
			LEFT JOIN Layer p ON l.parent_id = p.id
			LEFT JOIN Namespace n ON l.namespace_id = n.id
		WHERE l.name = ?`

	//TODO:
	searchLayerFeatureVersion = `
        SELECT ldf.featureversion_id, ldf.modification, fn.id, fn.name, f.id, f.name, fv.id, fv.version, ltree.id, ltree.name
        FROM Layer_diff_FeatureVersion ldf
        JOIN (
		SELECT h.id,h.name,h.parent_id FROM (SELECT @Id AS tempId,name,(SELECT @Id := parent_id FROM Layer WHERE Id = tempId) AS parent_id FROM(SELECT @Id := ?)initializeVars, Layer h WHERE @Id <> 0)a INNER JOIN Layer h ON h.Id = a.tempId order by h.id desc
        ) AS ltree  ON ldf.layer_id = ltree.id, FeatureVersion fv, Feature f, Namespace fn
        WHERE ldf.featureversion_id = fv.id AND fv.feature_id = f.id AND f.namespace_id = fn.id
        ORDER BY ltree.id`

	searchFeatureVersionVulnerability = `
			SELECT vafv.featureversion_id, v.id, v.name, v.description, v.link, v.severity, v.metadata,
				vn.name, vfif.version
			FROM Vulnerability_Affects_FeatureVersion vafv, Vulnerability v,
					 Namespace vn, Vulnerability_FixedIn_Feature vfif
			WHERE vafv.featureversion_id  IN (%s)
						AND vfif.vulnerability_id = v.id
						AND vafv.fixedin_id = vfif.id
						AND v.namespace_id = vn.id
						AND v.deleted_at IS NULL`

	insertLayer = `
		INSERT INTO Layer(name, engineversion, parent_id, namespace_id, created_at)
    VALUES(?, ?, ?, ?, CURRENT_TIMESTAMP)
    `
	getLayerId = `select id from Layer where name=?`

	updateLayer = `UPDATE Layer SET engineversion = ?, namespace_id = ? WHERE id = ?`

	removeLayerDiffFeatureVersion = `
		DELETE FROM Layer_diff_FeatureVersion
		WHERE layer_id = ?`

	insertLayerDiffFeatureVersion = `
		INSERT INTO Layer_diff_FeatureVersion(layer_id, featureversion_id, modification)
			SELECT ?, fv.id, ?
			FROM FeatureVersion fv
			WHERE fv.id in(%s)`

	removeLayer = `DELETE FROM Layer WHERE name = ?`

	// lock.go
	insertLock        = "INSERT INTO `Lock`(name, owner, until) VALUES(?, ?, ?)"
	searchLock        = "SELECT owner, until FROM `Lock` WHERE name = ?"
	updateLock        = "UPDATE `Lock` SET until = ? WHERE name = ? AND owner = ?"
	removeLock        = "DELETE FROM `Lock` WHERE name = ? AND owner = ?"
	removeLockExpired = "DELETE FROM `Lock` WHERE until < CURRENT_TIMESTAMP"

	// vulnerability.go
	searchVulnerabilityBase = `
	  SELECT v.id, v.name, n.id, n.name, v.description, v.link, v.severity, v.metadata
	  FROM Vulnerability v JOIN Namespace n ON v.namespace_id = n.id`
	searchVulnerabilityForUpdate          = ` FOR UPDATE `
	searchVulnerabilityByNamespaceAndName = ` WHERE n.name = ? AND v.name = ? AND v.deleted_at IS NULL`
	searchVulnerabilityByID               = ` WHERE v.id = ?`
	searchVulnerabilityByNamespace        = ` WHERE n.name = ? AND v.deleted_at IS NULL
 		  				  AND v.id >= ?
 						  ORDER BY v.id
 						  LIMIT ?`

	searchVulnerabilityFixedIn = `
		SELECT vfif.version, f.id, f.Name
		FROM Vulnerability_FixedIn_Feature vfif JOIN Feature f ON vfif.feature_id = f.id
		WHERE vfif.vulnerability_id = ?`

	insertVulnerability = `
		INSERT INTO Vulnerability(namespace_id, name, description, link, severity, metadata, created_at)
		VALUES(?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
	`
	getVulId                          = `select id from Vulnerability where namespace_id=? and name=?`
	getVulIdWithNamespaceName         = `select id from Vulnerability where namespace_id=(select id from Namespace where name=?) and name=? and deleted_at IS NULL`
	insertVulnerabilityFixedInFeature = `
		INSERT INTO Vulnerability_FixedIn_Feature(vulnerability_id, feature_id, version)
		VALUES(?, ?, ?)
	`
	findVulnerabilityFixedInFeature = `select id from Vulnerability_FixedIn_Feature where vulnerability_id=? AND feature_id=? AND version=?`

	searchFeatureVersionByFeature = `SELECT id, version FROM FeatureVersion WHERE feature_id = ?`

	removeVulnerability = `
		UPDATE Vulnerability
    SET deleted_at = CURRENT_TIMESTAMP
    WHERE namespace_id = (SELECT id FROM Namespace WHERE name = ?)
          AND name = ?
          AND deleted_at IS NULL`

	// notification.go
	insertNotification = `
		INSERT INTO Vulnerability_Notification(name, created_at, old_vulnerability_id, new_vulnerability_id)
    VALUES(?, CURRENT_TIMESTAMP, ?, ?)`

	updatedNotificationNotified = `
		UPDATE Vulnerability_Notification
		SET notified_at = CURRENT_TIMESTAMP
		WHERE name = ?`

	removeNotification = `
		UPDATE Vulnerability_Notification
	  SET deleted_at = CURRENT_TIMESTAMP
	  WHERE name = ?`

	searchNotificationAvailable = "	SELECT id, name, created_at, notified_at, deleted_at" +
		" FROM Vulnerability_Notification" +
		" WHERE (notified_at IS NULL OR notified_at < ?)" +
		" AND deleted_at IS NULL" +
		" AND name NOT IN (SELECT name FROM `Lock`)" +
		" ORDER BY Rand()" +
		" LIMIT 1"

	searchNotification = `
		SELECT id, name, created_at, notified_at, deleted_at, old_vulnerability_id, new_vulnerability_id
		FROM Vulnerability_Notification
		WHERE name = ?`

	searchNotificationLayerIntroducingVulnerability = `
		SELECT l.ID, l.name
		FROM Vulnerability v, Vulnerability_Affects_FeatureVersion vafv, FeatureVersion fv, Layer_diff_FeatureVersion ldfv, Layer l
		WHERE v.id = ?
					AND v.id = vafv.vulnerability_id
					AND vafv.featureversion_id = fv.id
					AND fv.id = ldfv.featureversion_id
					AND ldfv.modification = 'add'
					AND ldfv.layer_id = l.id
					AND l.id >= ?
		ORDER BY l.ID
		LIMIT ?`

	// complex_test.go
	searchComplexTestFeatureVersionAffects = `
		SELECT v.name
    FROM FeatureVersion fv
      LEFT JOIN Vulnerability_Affects_FeatureVersion vaf ON fv.id = vaf.featureversion_id
      JOIN Vulnerability v ON vaf.vulnerability_id = v.id
    WHERE featureversion_id = ?`
)

// buildInputArray constructs a PostgreSQL input array from the specified integers.
// Useful to use the `= ANY($1::integer[])` syntax that let us use a IN clause while using
// a single placeholder.
func buildInputArray(ints []int) string {
	str := ""
	for i := 0; i < len(ints)-1; i++ {
		str = str + strconv.Itoa(ints[i]) + ","
	}
	str = str + strconv.Itoa(ints[len(ints)-1])
	return str
}
