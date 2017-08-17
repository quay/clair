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

	"github.com/lib/pq"
	log "github.com/sirupsen/logrus"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/ext/versionfmt"
	"github.com/coreos/clair/pkg/commonerr"
)

var (
	errFeatureNotFound = errors.New("Feature not found")
)

type vulnerabilityAffecting struct {
	vulnerabilityID int64
	addedByID       int64
}

func (tx *pgSession) PersistFeatures(features []database.Feature) error {
	if len(features) == 0 {
		return nil
	}

	// Sorting is needed before inserting into database to prevent deadlock.
	sort.Slice(features, func(i, j int) bool {
		return features[i].Name < features[j].Name ||
			features[i].Version < features[j].Version ||
			features[i].VersionFormat < features[j].VersionFormat
	})

	// TODO(Sida): A better interface for bulk insertion is needed.
	keys := make([]interface{}, len(features)*3)
	for i, f := range features {
		keys[i*3] = f.Name
		keys[i*3+1] = f.Version
		keys[i*3+2] = f.VersionFormat
		if f.Name == "" || f.Version == "" || f.VersionFormat == "" {
			return commonerr.NewBadRequestError("Empty feature name, version or version format is not allowed")
		}
	}

	_, err := tx.Exec(queryPersistFeature(len(features)), keys...)
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
			return nil, errFeatureNotFound
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

	keys := make([]interface{}, len(cache)*3)
	for i, c := range cache {
		keys[i*3] = c.vulnID
		keys[i*3+1] = c.nsFeatureID
		keys[i*3+2] = c.vulnAffectingID
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
				return errFeatureNotFound
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
				return errNamespaceNotFound
			}
			nsIDs[nsToFind[i]] = id
		}
	} else {
		return err
	}

	keys := make([]interface{}, len(features)*2)
	for i, f := range features {
		keys[i*2] = fIDs[f.Feature]
		keys[i*2+1] = nsIDs[f.Namespace]
	}

	_, err := tx.Exec(queryPersistNamespacedFeature(len(features)), keys...)
	if err != nil {
		return err
	}

	return nil
}

// FindAffectedNamespacedFeatures looks up cache table and retrieves all
// vulnerabilities associated with the features.
func (tx *pgSession) FindAffectedNamespacedFeatures(features []database.NamespacedFeature) ([]database.NullableAffectedNamespacedFeature, error) {
	if len(features) == 0 {
		return nil, nil
	}

	returnFeatures := make([]database.NullableAffectedNamespacedFeature, len(features))

	// featureMap is used to keep track of duplicated features.
	featureMap := map[database.NamespacedFeature][]*database.NullableAffectedNamespacedFeature{}
	// initialize return value and generate unique feature request queries.
	for i, f := range features {
		returnFeatures[i] = database.NullableAffectedNamespacedFeature{
			AffectedNamespacedFeature: database.AffectedNamespacedFeature{
				NamespacedFeature: f,
			},
		}

		featureMap[f] = append(featureMap[f], &returnFeatures[i])
	}

	// query unique namespaced features
	distinctFeatures := []database.NamespacedFeature{}
	for f := range featureMap {
		distinctFeatures = append(distinctFeatures, f)
	}

	nsFeatureIDs, err := tx.findNamespacedFeatureIDs(distinctFeatures)
	if err != nil {
		return nil, err
	}

	toQuery := []int64{}
	featureIDMap := map[int64][]*database.NullableAffectedNamespacedFeature{}
	for i, id := range nsFeatureIDs {
		if id.Valid {
			toQuery = append(toQuery, id.Int64)
			for _, f := range featureMap[distinctFeatures[i]] {
				f.Valid = id.Valid
				featureIDMap[id.Int64] = append(featureIDMap[id.Int64], f)
			}
		}
	}

	rows, err := tx.Query(searchNamespacedFeaturesVulnerabilities, pq.Array(toQuery))
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

		for _, f := range featureIDMap[featureID] {
			f.AffectedBy = append(f.AffectedBy, vuln)
		}
	}

	return returnFeatures, nil
}

func (tx *pgSession) findNamespacedFeatureIDs(nfs []database.NamespacedFeature) ([]sql.NullInt64, error) {
	if len(nfs) == 0 {
		return nil, nil
	}

	nfsMap := map[database.NamespacedFeature]sql.NullInt64{}
	keys := make([]interface{}, len(nfs)*4)
	for i, nf := range nfs {
		keys[i*4] = nfs[i].Name
		keys[i*4+1] = nfs[i].Version
		keys[i*4+2] = nfs[i].VersionFormat
		keys[i*4+3] = nfs[i].Namespace.Name
		nfsMap[nf] = sql.NullInt64{}
	}

	rows, err := tx.Query(querySearchNamespacedFeature(len(nfs)), keys...)
	if err != nil {
		return nil, handleError("searchNamespacedFeature", err)
	}

	defer rows.Close()
	var (
		id sql.NullInt64
		nf database.NamespacedFeature
	)

	for rows.Next() {
		err := rows.Scan(&id, &nf.Name, &nf.Version, &nf.VersionFormat, &nf.Namespace.Name)
		nf.Namespace.VersionFormat = nf.VersionFormat
		if err != nil {
			return nil, handleError("searchNamespacedFeature", err)
		}
		nfsMap[nf] = id
	}

	ids := make([]sql.NullInt64, len(nfs))
	for i, nf := range nfs {
		ids[i] = nfsMap[nf]
	}

	return ids, nil
}

func (tx *pgSession) findFeatureIDs(fs []database.Feature) ([]sql.NullInt64, error) {
	if len(fs) == 0 {
		return nil, nil
	}

	fMap := map[database.Feature]sql.NullInt64{}

	keys := make([]interface{}, len(fs)*3)
	for i, f := range fs {
		keys[i*3] = f.Name
		keys[i*3+1] = f.Version
		keys[i*3+2] = f.VersionFormat
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
		err := rows.Scan(&id, &f.Name, &f.Version, &f.VersionFormat)
		if err != nil {
			return nil, handleError("querySearchFeatureID", err)
		}
		fMap[f] = id
	}

	ids := make([]sql.NullInt64, len(fs))
	for i, f := range fs {
		ids[i] = fMap[f]
	}

	return ids, nil
}
