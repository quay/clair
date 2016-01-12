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
		if id, found := pgSQL.cache.Get("feature:" + feature.Name); found {
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
		pgSQL.cache.Add("feature:"+feature.Name, id)
	}

	return id, nil
}

func (pgSQL *pgSQL) insertFeatureVersion(featureVersion database.FeatureVersion) (id int, err error) {
	if featureVersion.Version.String() == "" {
		return 0, cerrors.NewBadRequestError("could not find/insert invalid FeatureVersion")
	}

	if pgSQL.cache != nil {
		if id, found := pgSQL.cache.Get("featureversion:" + featureVersion.Feature.Name + ":" +
			featureVersion.Version.String()); found {
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
	_, err = tx.Exec(getQuery("set_tx_serializable"))
	if err != nil {
		tx.Rollback()
		return 0, handleError("insertFeatureVersion.set_tx_serializable", err)
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
		return featureVersion.ID, nil
	}

	// Link the new FeatureVersion with every vulnerabilities that affect it, by inserting in
	// Vulnerability_Affects_FeatureVersion.
	err = linkFeatureVersionToVulnerabilities(tx, featureVersion)
	if err != nil {
		// tx.Rollback() is done in linkFeatureVersionToVulnerabilities.
		return 0, err
	}

	// Commit transaction.
	err = tx.Commit()
	if err != nil {
		return 0, handleError("insertFeatureVersion.Commit()", err)
	}

	if pgSQL.cache != nil {
		pgSQL.cache.Add("featureversion:"+featureVersion.Feature.Name+":"+
			featureVersion.Version.String(), featureVersion.ID)
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

func linkFeatureVersionToVulnerabilities(tx *sql.Tx, featureVersion database.FeatureVersion) error {
	// Select every vulnerability and the fixed version that affect this Feature.
	// TODO(Quentin-M): LIMIT
	rows, err := tx.Query(getQuery("s_vulnerability_fixedin_feature"), featureVersion.Feature.ID)
	if err != nil {
		tx.Rollback()
		return handleError("s_vulnerability_fixedin_feature", err)
	}
	defer rows.Close()

	var fixedInID, vulnerabilityID int
	var fixedInVersion types.Version
	for rows.Next() {
		err := rows.Scan(&fixedInID, &vulnerabilityID, &fixedInVersion)
		if err != nil {
			tx.Rollback()
			return handleError("s_vulnerability_fixedin_feature.Scan()", err)
		}

		if featureVersion.Version.Compare(fixedInVersion) < 0 {
			// The version of the FeatureVersion we are inserting is lower than the fixed version on this
			// Vulnerability, thus, this FeatureVersion is affected by it.
			// TODO(Quentin-M): Prepare.
			_, err := tx.Exec(getQuery("i_vulnerability_affects_featureversion"), vulnerabilityID,
				featureVersion.ID, fixedInID)
			if err != nil {
				tx.Rollback()
				return handleError("i_vulnerability_affects_featureversion", err)
			}
		}
	}
	if err = rows.Err(); err != nil {
		tx.Rollback()
		return handleError("s_vulnerability_fixedin_feature.Rows()", err)
	}

	return nil
}
