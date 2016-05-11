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

import (
	"database/sql"
	"time"

	"github.com/coreos/clair/database"
	cerrors "github.com/coreos/clair/utils/errors"
	"github.com/coreos/clair/utils/types"
)

func (mySQL *mySQL) insertFeatureiWithTransaction(queryer Queryer, feature database.Feature) (int, error) {
	if feature.Name == "" {
		return 0, cerrors.NewBadRequestError("could not find/insert invalid Feature")
	}

	// Do cache lookup.
	if mySQL.cache != nil {
		database.PromCacheQueriesTotal.WithLabelValues("feature").Inc()
		id, found := mySQL.cache.Get("feature:" + feature.Namespace.Name + ":" + feature.Name)
		if found {
			database.PromCacheHitsTotal.WithLabelValues("feature").Inc()
			return id.(int), nil
		}
	}

	// We do `defer database.ObserveQueryTime` here because we don't want to observe cached features.
	defer database.ObserveQueryTime("insertFeature", "all", time.Now())

	// Find or create Namespace.
	namespaceID, err := mySQL.insertNamespaceWithTransaction(queryer, feature.Namespace)
	if err != nil {
		return 0, err
	}
	// Find or create Feature.
	var id int
	res, err := queryer.Exec(insertFeature, feature.Name, namespaceID, feature.Name, namespaceID)
	if err != nil {
		return 0, handleError("insertFeatureVersion", err)
	}
	tmpid, err := res.LastInsertId()
	if err != nil {
		return 0, handleError("insertFeatureVersion", err)
	}
	id = int(tmpid)
	// if id==0 means the feature already exists, use query to get id
	if id == 0 {
		err = queryer.QueryRow(soiFeature, feature.Name, namespaceID).Scan(&id)
		if err != nil {
			return 0, handleError("soiFeature", err)
		}
	}
	if mySQL.cache != nil {
		mySQL.cache.Add("feature:"+feature.Namespace.Name+":"+feature.Name, id)
	}

	return id, nil
}

func (mySQL *mySQL) insertFeature(feature database.Feature) (int, error) {
	if feature.Name == "" {
		return 0, cerrors.NewBadRequestError("could not find/insert invalid Feature")
	}

	// Do cache lookup.
	if mySQL.cache != nil {
		database.PromCacheQueriesTotal.WithLabelValues("feature").Inc()
		id, found := mySQL.cache.Get("feature:" + feature.Namespace.Name + ":" + feature.Name)
		if found {
			database.PromCacheHitsTotal.WithLabelValues("feature").Inc()
			return id.(int), nil
		}
	}

	// We do `defer database.ObserveQueryTime` here because we don't want to observe cached features.
	defer database.ObserveQueryTime("insertFeature", "all", time.Now())

	// Find or create Namespace.
	namespaceID, err := mySQL.insertNamespace(feature.Namespace)
	if err != nil {
		return 0, err
	}
	// Find or create Feature.
	var id int
	res, err := mySQL.Exec(insertFeature, feature.Name, namespaceID, feature.Name, namespaceID)
	if err != nil {
		return 0, handleError("insertFeatureVersion", err)
	}
	tmpid, err := res.LastInsertId()
	if err != nil {
		return 0, handleError("insertFeatureVersion", err)
	}
	id = int(tmpid)
	// if id==0 means the feature already exists, use query to get id
	if id == 0 {
		err = mySQL.QueryRow(soiFeature, feature.Name, namespaceID).Scan(&id)
		if err != nil {
			return 0, handleError("soiFeature", err)
		}
	}
	if mySQL.cache != nil {
		mySQL.cache.Add("feature:"+feature.Namespace.Name+":"+feature.Name, id)
	}

	return id, nil
}

func (mySQL *mySQL) insertFeatureVersion(featureVersion database.FeatureVersion) (id int, err error) {
	if featureVersion.Version.String() == "" {
		return 0, cerrors.NewBadRequestError("could not find/insert invalid FeatureVersion")
	}

	// Do cache lookup.
	cacheIndex := "featureversion:" + featureVersion.Feature.Namespace.Name + ":" + featureVersion.Feature.Name + ":" + featureVersion.Version.String()
	if mySQL.cache != nil {
		database.PromCacheQueriesTotal.WithLabelValues("featureversion").Inc()
		id, found := mySQL.cache.Get(cacheIndex)
		if found {
			database.PromCacheHitsTotal.WithLabelValues("featureversion").Inc()
			return id.(int), nil
		}
	}

	// We do `defer database.ObserveQueryTime` here because we don't want to observe cached featureversions.
	defer database.ObserveQueryTime("insertFeatureVersion", "all", time.Now())

	// Find or create Feature first.
	t := time.Now()
	featureID, err := mySQL.insertFeature(featureVersion.Feature)
	database.ObserveQueryTime("insertFeatureVersion", "insertFeature", t)

	if err != nil {
		return 0, err
	}

	featureVersion.Feature.ID = featureID

	// Try to find the FeatureVersion.
	//
	// In a populated database, the likelihood of the FeatureVersion already being there is high.
	// If we can find it here, we then avoid using a transaction and locking the database.
	err = mySQL.QueryRow(searchFeatureVersion, featureID, &featureVersion.Version).
		Scan(&featureVersion.ID)
	if err != nil && err != sql.ErrNoRows {
		return 0, handleError("searchFeatureVersion", err)
	}
	if err == nil {
		if mySQL.cache != nil {
			mySQL.cache.Add(cacheIndex, featureVersion.ID)
		}

		return featureVersion.ID, nil
	}

	// Begin transaction.
	tx, err := mySQL.Begin()
	if err != nil {
		tx.Rollback()
		return 0, handleError("insertFeatureVersion.Begin()", err)
	}

	// Lock Vulnerability_Affects_FeatureVersion exclusively.
	// We want to prevent InsertVulnerability to modify it.
	database.PromConcurrentLockVAFV.Inc()
	defer database.PromConcurrentLockVAFV.Dec()
	t = time.Now()
	var tmp int64
	err = tx.QueryRow(lockVulnerabilityAffects).Scan(&tmp)
	database.ObserveQueryTime("insertFeatureVersion", "lock", t)

	if err != nil {
		tx.Rollback()
		return 0, handleError("insertFeatureVersion.lockVulnerabilityAffects", err)
	}
	// Find or create FeatureVersion.
	var newOrExisting string
	t = time.Now()
	_, err = tx.Exec(insertFeatureVersion, featureID, &featureVersion.Version, featureID, &featureVersion.Version)
	database.ObserveQueryTime("insertFeatureVersion", "soiFeatureVersion", t)
	if err != nil {
		tx.Rollback()
		return 0, handleError("insertFeatureVersion", err)
	}

	t = time.Now()
	err = tx.QueryRow(soiFeatureVersion, featureID, &featureVersion.Version).
		Scan(&newOrExisting, &featureVersion.ID)
	database.ObserveQueryTime("insertFeatureVersion", "soiFeatureVersion", t)

	if err != nil {
		tx.Rollback()
		return 0, handleError("soiFeatureVersion", err)
	}

	if newOrExisting == "exi" {
		// That featureVersion already exists, return its id.
		tx.Commit()

		if mySQL.cache != nil {
			mySQL.cache.Add(cacheIndex, featureVersion.ID)
		}

		return featureVersion.ID, nil
	}

	// Link the new FeatureVersion with every vulnerabilities that affect it, by inserting in
	// Vulnerability_Affects_FeatureVersion.
	t = time.Now()
	err = linkFeatureVersionToVulnerabilities(tx, featureVersion)
	database.ObserveQueryTime("insertFeatureVersion", "linkFeatureVersionToVulnerabilities", t)

	if err != nil {
		tx.Rollback()
		return 0, err
	}

	// Commit transaction.
	err = tx.Commit()
	if err != nil {
		return 0, handleError("insertFeatureVersion.Commit()", err)
	}

	if mySQL.cache != nil {
		mySQL.cache.Add(cacheIndex, featureVersion.ID)
	}

	return featureVersion.ID, nil
}

// TODO(Quentin-M): Batch me
func (mySQL *mySQL) insertFeatureVersions(featureVersions []database.FeatureVersion) ([]int, error) {
	IDs := make([]int, 0, len(featureVersions))

	for i := 0; i < len(featureVersions); i++ {
		id, err := mySQL.insertFeatureVersion(featureVersions[i])
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
			featureVersion.ID, affect.fixedInID, affect.vulnerabilityID, featureVersion.ID, affect.fixedInID)
		if err != nil {
			return handleError("insertVulnerabilityAffectsFeatureVersion", err)
		}
	}

	return nil
}
