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
	"sort"

	"github.com/lib/pq"
	log "github.com/sirupsen/logrus"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/ext/versionfmt"
	"github.com/coreos/clair/pkg/commonerr"
)

const (
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
			AND vaf.feature_type = f.type
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
)

func (tx *pgSession) PersistFeatures(features []database.Feature) error {
	if len(features) == 0 {
		return nil
	}

	types, err := tx.getFeatureTypeMap()
	if err != nil {
		return err
	}

	// Sorting is needed before inserting into database to prevent deadlock.
	sort.Slice(features, func(i, j int) bool {
		return features[i].Name < features[j].Name ||
			features[i].Version < features[j].Version ||
			features[i].VersionFormat < features[j].VersionFormat
	})

	// TODO(Sida): A better interface for bulk insertion is needed.
	keys := make([]interface{}, 0, len(features)*3)
	for _, f := range features {
		keys = append(keys, f.Name, f.Version, f.VersionFormat, types.byName[f.Type])
		if f.Name == "" || f.Version == "" || f.VersionFormat == "" {
			return commonerr.NewBadRequestError("Empty feature name, version or version format is not allowed")
		}
	}

	_, err = tx.Exec(queryPersistFeature(len(features)), keys...)
	return handleError("queryPersistFeature", err)
}

type namespacedFeatureWithID struct {
	database.NamespacedFeature

	ID int64
}

type vulnerabilityCache struct {
	nsFeatureID     int64
	vulnID          int64
	vulnAffectingID int64
}

func (tx *pgSession) searchAffectingVulnerabilities(features []database.NamespacedFeature) ([]vulnerabilityCache, error) {
	if len(features) == 0 {
		return nil, nil
	}

	ids, err := tx.findNamespacedFeatureIDs(features)
	if err != nil {
		return nil, err
	}

	fMap := map[int64]database.NamespacedFeature{}
	for i, f := range features {
		if !ids[i].Valid {
			return nil, database.ErrMissingEntities
		}
		fMap[ids[i].Int64] = f
	}

	cacheTable := []vulnerabilityCache{}
	rows, err := tx.Query(searchPotentialAffectingVulneraibilities, pq.Array(ids))
	if err != nil {
		return nil, handleError("searchPotentialAffectingVulneraibilities", err)
	}

	defer rows.Close()
	for rows.Next() {
		var (
			cache    vulnerabilityCache
			affected string
		)

		err := rows.Scan(&cache.nsFeatureID, &cache.vulnID, &affected, &cache.vulnAffectingID)
		if err != nil {
			return nil, err
		}

		if ok, err := versionfmt.InRange(fMap[cache.nsFeatureID].VersionFormat, fMap[cache.nsFeatureID].Version, affected); err != nil {
			return nil, err
		} else if ok {
			cacheTable = append(cacheTable, cache)
		}
	}

	return cacheTable, nil
}

func (tx *pgSession) CacheAffectedNamespacedFeatures(features []database.NamespacedFeature) error {
	if len(features) == 0 {
		return nil
	}

	_, err := tx.Exec(lockVulnerabilityAffects)
	if err != nil {
		return handleError("lockVulnerabilityAffects", err)
	}

	cache, err := tx.searchAffectingVulnerabilities(features)

	keys := make([]interface{}, 0, len(cache)*3)
	for _, c := range cache {
		keys = append(keys, c.vulnID, c.nsFeatureID, c.vulnAffectingID)
	}

	if len(cache) == 0 {
		return nil
	}

	affected, err := tx.Exec(queryPersistVulnerabilityAffectedNamespacedFeature(len(cache)), keys...)
	if err != nil {
		return handleError("persistVulnerabilityAffectedNamespacedFeature", err)
	}
	if count, err := affected.RowsAffected(); err != nil {
		log.Debugf("Cached %d features in vulnerability_affected_namespaced_feature", count)
	}
	return nil
}

func (tx *pgSession) PersistNamespacedFeatures(features []database.NamespacedFeature) error {
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

	if ids, err := tx.findFeatureIDs(fToFind); err == nil {
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

	if ids, err := tx.findNamespaceIDs(nsToFind); err == nil {
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

// FindAffectedNamespacedFeatures retrieves vulnerabilities associated with the
// feature.
func (tx *pgSession) FindAffectedNamespacedFeatures(features []database.NamespacedFeature) ([]database.NullableAffectedNamespacedFeature, error) {
	if len(features) == 0 {
		return nil, nil
	}

	vulnerableFeatures := make([]database.NullableAffectedNamespacedFeature, len(features))
	featureIDs, err := tx.findNamespacedFeatureIDs(features)
	if err != nil {
		return nil, err
	}

	for i, id := range featureIDs {
		if id.Valid {
			vulnerableFeatures[i].Valid = true
			vulnerableFeatures[i].NamespacedFeature = features[i]
		}
	}

	rows, err := tx.Query(searchNamespacedFeaturesVulnerabilities, pq.Array(featureIDs))
	if err != nil {
		return nil, handleError("searchNamespacedFeaturesVulnerabilities", err)
	}

	defer rows.Close()

	for rows.Next() {
		var (
			featureID int64
			vuln      database.VulnerabilityWithFixedIn
		)

		err := rows.Scan(&featureID,
			&vuln.Name,
			&vuln.Description,
			&vuln.Link,
			&vuln.Severity,
			&vuln.Metadata,
			&vuln.FixedInVersion,
			&vuln.Namespace.Name,
			&vuln.Namespace.VersionFormat,
		)

		if err != nil {
			return nil, handleError("searchNamespacedFeaturesVulnerabilities", err)
		}

		for i, id := range featureIDs {
			if id.Valid && id.Int64 == featureID {
				vulnerableFeatures[i].AffectedNamespacedFeature.AffectedBy = append(vulnerableFeatures[i].AffectedNamespacedFeature.AffectedBy, vuln)
			}
		}
	}

	return vulnerableFeatures, nil
}

func (tx *pgSession) findNamespacedFeatureIDs(nfs []database.NamespacedFeature) ([]sql.NullInt64, error) {
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
		return nil, handleError("searchNamespacedFeature", err)
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
			return nil, handleError("searchNamespacedFeature", err)
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

func (tx *pgSession) findFeatureIDs(fs []database.Feature) ([]sql.NullInt64, error) {
	if len(fs) == 0 {
		return nil, nil
	}

	types, err := tx.getFeatureTypeMap()
	if err != nil {
		return nil, err
	}

	fMap := map[database.Feature]sql.NullInt64{}

	keys := make([]interface{}, 0, len(fs)*4)
	for _, f := range fs {
		typeID := types.byName[f.Type]
		keys = append(keys, f.Name, f.Version, f.VersionFormat, typeID)
		fMap[f] = sql.NullInt64{}
	}

	rows, err := tx.Query(querySearchFeatureID(len(fs)), keys...)
	if err != nil {
		return nil, handleError("querySearchFeatureID", err)
	}
	defer rows.Close()

	var (
		id sql.NullInt64
		f  database.Feature
	)
	for rows.Next() {
		var typeID int
		err := rows.Scan(&id, &f.Name, &f.Version, &f.VersionFormat, &typeID)
		if err != nil {
			return nil, handleError("querySearchFeatureID", err)
		}

		f.Type = types.byID[typeID]
		fMap[f] = id
	}

	ids := make([]sql.NullInt64, len(fs))
	for i, f := range fs {
		ids[i] = fMap[f]
	}

	return ids, nil
}
