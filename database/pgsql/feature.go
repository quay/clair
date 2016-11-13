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
	"database/sql"
	"time"

	"github.com/coreos/clair/database"
	cerrors "github.com/coreos/clair/utils/errors"
	"github.com/coreos/clair/utils/types"
)

func (pgSQL *pgSQL) insertFeature(feature database.Feature) (int, error) {
	if feature.Name == "" {
		return 0, cerrors.NewBadRequestError("could not find/insert invalid Feature")
	}

	// Do cache lookup.
	if pgSQL.cache != nil {
		promCacheQueriesTotal.WithLabelValues("feature").Inc()
		id, found := pgSQL.cache.Get("feature:" + feature.Namespace.Name + ":" + feature.Name)
		if found {
			promCacheHitsTotal.WithLabelValues("feature").Inc()
			return id.(int), nil
		}
	}

	// We do `defer observeQueryTime` here because we don't want to observe cached features.
	defer observeQueryTime("insertFeature", "all", time.Now())

	// Find or create Namespace.
	namespaceID, err := pgSQL.insertNamespace(feature.Namespace)
	if err != nil {
		return 0, err
	}

	// Find or create Feature.
	var id int
	err = pgSQL.QueryRow(soiFeature, feature.Name, namespaceID).Scan(&id)
	if err != nil {
		return 0, handleError("soiFeature", err)
	}

	if pgSQL.cache != nil {
		pgSQL.cache.Add("feature:"+feature.Namespace.Name+":"+feature.Name, id)
	}

	return id, nil
}

func (pgSQL *pgSQL) insertFeatureVersion(featureVersion database.FeatureVersion) (id int, err error) {
	if featureVersion.Version.String() == "" {
		return 0, cerrors.NewBadRequestError("could not find/insert invalid FeatureVersion")
	}

	// Do cache lookup.
	cacheIndex := "featureversion:" + featureVersion.Feature.Namespace.Name + ":" + featureVersion.Feature.Name + ":" + featureVersion.Version.String()
	if pgSQL.cache != nil {
		promCacheQueriesTotal.WithLabelValues("featureversion").Inc()
		id, found := pgSQL.cache.Get(cacheIndex)
		if found {
			promCacheHitsTotal.WithLabelValues("featureversion").Inc()
			return id.(int), nil
		}
	}

	// We do `defer observeQueryTime` here because we don't want to observe cached featureversions.
	defer observeQueryTime("insertFeatureVersion", "all", time.Now())

	// Find or create Feature first.
	t := time.Now()
	featureID, err := pgSQL.insertFeature(featureVersion.Feature)
	observeQueryTime("insertFeatureVersion", "insertFeature", t)

	if err != nil {
		return 0, err
	}

	featureVersion.Feature.ID = featureID

	// Try to find the FeatureVersion.
	//
	// In a populated database, the likelihood of the FeatureVersion already being there is high.
	// If we can find it here, we then avoid using a transaction and locking the database.
	err = pgSQL.QueryRow(searchFeatureVersion, featureID, &featureVersion.Version).
		Scan(&featureVersion.ID)
	if err != nil && err != sql.ErrNoRows {
		return 0, handleError("searchFeatureVersion", err)
	}
	if err == nil {
		if pgSQL.cache != nil {
			pgSQL.cache.Add(cacheIndex, featureVersion.ID)
		}

		return featureVersion.ID, nil
	}

	// Begin transaction.
	tx, err := pgSQL.Begin()
	if err != nil {
		tx.Rollback()
		return 0, handleError("insertFeatureVersion.Begin()", err)
	}

	// Lock Vulnerability_Affects_FeatureVersion exclusively.
	// We want to prevent InsertVulnerability to modify it.
	promConcurrentLockVAFV.Inc()
	defer promConcurrentLockVAFV.Dec()
	t = time.Now()
	_, err = tx.Exec(lockVulnerabilityAffects)
	observeQueryTime("insertFeatureVersion", "lock", t)

	if err != nil {
		tx.Rollback()
		return 0, handleError("insertFeatureVersion.lockVulnerabilityAffects", err)
	}

	// Find or create FeatureVersion.
	var created bool

	t = time.Now()
	err = tx.QueryRow(soiFeatureVersion, featureID, &featureVersion.Version).
		Scan(&created, &featureVersion.ID)
	observeQueryTime("insertFeatureVersion", "soiFeatureVersion", t)

	if err != nil {
		tx.Rollback()
		return 0, handleError("soiFeatureVersion", err)
	}

	if !created {
		// The featureVersion already existed, no need to link it to
		// vulnerabilities.
		tx.Commit()

		if pgSQL.cache != nil {
			pgSQL.cache.Add(cacheIndex, featureVersion.ID)
		}

		return featureVersion.ID, nil
	}

	// Link the new FeatureVersion with every vulnerabilities that affect it, by inserting in
	// Vulnerability_Affects_FeatureVersion.
	t = time.Now()
	err = linkFeatureVersionToVulnerabilities(tx, featureVersion)
	observeQueryTime("insertFeatureVersion", "linkFeatureVersionToVulnerabilities", t)

	if err != nil {
		tx.Rollback()
		return 0, err
	}

	// Commit transaction.
	err = tx.Commit()
	if err != nil {
		return 0, handleError("insertFeatureVersion.Commit()", err)
	}

	if pgSQL.cache != nil {
		pgSQL.cache.Add(cacheIndex, featureVersion.ID)
	}

	return featureVersion.ID, nil
}

// TODO(Quentin-M): Batch me
func (pgSQL *pgSQL) insertFeatureVersions(featureVersions []database.FeatureVersion) ([]int, error) {
	IDs := make([]int, 0, len(featureVersions))

	for i := 0; i < len(featureVersions); i++ {
		id, err := pgSQL.insertFeatureVersion(featureVersions[i])
		if err != nil {
			return IDs, err
		}
		IDs = append(IDs, id)
	}

	return IDs, nil
}

type vulnerabilityAffectsFeatureVersion struct {
	vulnerabilityID int
	fixedInID       int
	fixedInVersion  types.Version
}

func linkFeatureVersionToVulnerabilities(tx *sql.Tx, featureVersion database.FeatureVersion) error {
	// Select every vulnerability and the fixed version that affect this Feature.
	// TODO(Quentin-M): LIMIT
	rows, err := tx.Query(searchVulnerabilityFixedInFeature, featureVersion.Feature.ID)
	if err != nil {
		return handleError("searchVulnerabilityFixedInFeature", err)
	}
	defer rows.Close()

	var affects []vulnerabilityAffectsFeatureVersion
	for rows.Next() {
		var affect vulnerabilityAffectsFeatureVersion

		err := rows.Scan(&affect.fixedInID, &affect.vulnerabilityID, &affect.fixedInVersion)
		if err != nil {
			return handleError("searchVulnerabilityFixedInFeature.Scan()", err)
		}

		if featureVersion.Version.Compare(affect.fixedInVersion) < 0 {
			// The version of the FeatureVersion we are inserting is lower than the fixed version on this
			// Vulnerability, thus, this FeatureVersion is affected by it.
			affects = append(affects, affect)
		}
	}
	if err = rows.Err(); err != nil {
		return handleError("searchVulnerabilityFixedInFeature.Rows()", err)
	}
	rows.Close()

	// Insert into Vulnerability_Affects_FeatureVersion.
	for _, affect := range affects {
		// TODO(Quentin-M): Batch me.
		_, err := tx.Exec(insertVulnerabilityAffectsFeatureVersion, affect.vulnerabilityID,
			featureVersion.ID, affect.fixedInID)
		if err != nil {
			return handleError("insertVulnerabilityAffectsFeatureVersion", err)
		}
	}

	return nil
}
