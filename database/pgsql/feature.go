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

	"github.com/coreos/clair/database"
	cerrors "github.com/coreos/clair/utils/errors"
	"github.com/coreos/clair/utils/types"
)

func (pgSQL *pgSQL) insertFeature(feature database.Feature) (int, error) {
	if feature.Name == "" {
		return 0, cerrors.NewBadRequestError("could not find/insert invalid Feature")
	}

	if pgSQL.cache != nil {
		id, found := pgSQL.cache.Get("feature:" + feature.Namespace.Name + ":" + feature.Name)
		if found {
			return id.(int), nil
		}
	}

	// Find or create Namespace.
	namespaceID, err := pgSQL.insertNamespace(feature.Namespace)
	if err != nil {
		return 0, err
	}

	// Find or create Feature.
	var id int
	err = pgSQL.QueryRow(getQuery("soi_feature"), feature.Name, namespaceID).Scan(&id)
	if err != nil {
		return 0, handleError("soi_feature", err)
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

	if pgSQL.cache != nil {
		id, found := pgSQL.cache.Get("featureversion:" + featureVersion.Feature.Namespace.Name + ":" +
			featureVersion.Feature.Name + ":" + featureVersion.Version.String())
		if found {
			return id.(int), nil
		}
	}

	// Find or create Feature first.
	featureID, err := pgSQL.insertFeature(featureVersion.Feature)
	if err != nil {
		return 0, err
	}
	featureVersion.Feature.ID = featureID

	// Begin transaction.
	tx, err := pgSQL.Begin()
	if err != nil {
		tx.Rollback()
		return 0, handleError("insertFeatureVersion.Begin()", err)
	}

	// Set transaction as SERIALIZABLE.
	// This is how we ensure that the data in Vulnerability_Affects_FeatureVersion is always
	// consistent.
	_, err = tx.Exec(getQuery("l_vulnerability_affects_featureversion"))
	if err != nil {
		tx.Rollback()
		return 0, handleError("insertFeatureVersion.l_vulnerability_affects_featureversion", err)
	}

	// Find or create FeatureVersion.
	var newOrExisting string
	err = tx.QueryRow(getQuery("soi_featureversion"), featureID, &featureVersion.Version).
		Scan(&newOrExisting, &featureVersion.ID)
	if err != nil {
		tx.Rollback()
		return 0, handleError("soi_featureversion", err)
	}
	if newOrExisting == "exi" {
		// That featureVersion already exists, return its id.
		tx.Commit()
		return featureVersion.ID, nil
	}

	// Link the new FeatureVersion with every vulnerabilities that affect it, by inserting in
	// Vulnerability_Affects_FeatureVersion.
	err = linkFeatureVersionToVulnerabilities(tx, featureVersion)
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
		pgSQL.cache.Add("featureversion:"+featureVersion.Feature.Name+":"+
			featureVersion.Feature.Namespace.Name+":"+featureVersion.Version.String(), featureVersion.ID)
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
	rows, err := tx.Query(getQuery("s_vulnerability_fixedin_feature"), featureVersion.Feature.ID)
	if err != nil {
		return handleError("s_vulnerability_fixedin_feature", err)
	}
	defer rows.Close()

	var affects []vulnerabilityAffectsFeatureVersion
	for rows.Next() {
		var affect vulnerabilityAffectsFeatureVersion

		err := rows.Scan(&affect.fixedInID, &affect.vulnerabilityID, &affect.fixedInVersion)
		if err != nil {
			return handleError("s_vulnerability_fixedin_feature.Scan()", err)
		}

		if featureVersion.Version.Compare(affect.fixedInVersion) < 0 {
			// The version of the FeatureVersion we are inserting is lower than the fixed version on this
			// Vulnerability, thus, this FeatureVersion is affected by it.
			affects = append(affects, affect)
		}
	}
	if err = rows.Err(); err != nil {
		return handleError("s_vulnerability_fixedin_feature.Rows()", err)
	}
	rows.Close()

	// Insert into Vulnerability_Affects_FeatureVersion.
	for _, affect := range affects {
		// TODO(Quentin-M): Batch me.
		_, err := tx.Exec(getQuery("i_vulnerability_affects_featureversion"), affect.vulnerabilityID,
			featureVersion.ID, affect.fixedInID)
		if err != nil {
			return handleError("i_vulnerability_affects_featureversion", err)
		}
	}

	return nil
}
