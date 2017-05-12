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
	"strings"
	"time"

	"github.com/guregu/null/zero"
	log "github.com/sirupsen/logrus"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/pkg/commonerr"
)

func (pgSQL *pgSQL) FindLayer(name string, withFeatures, withVulnerabilities bool) (database.Layer, error) {
	subquery := "all"
	if withFeatures {
		subquery += "/features"
	} else if withVulnerabilities {
		subquery += "/features+vulnerabilities"
	}
	defer observeQueryTime("FindLayer", subquery, time.Now())

	// Find the layer
	var (
		layer           database.Layer
		parentID        zero.Int
		parentName      zero.String
		nsID            zero.Int
		nsName          sql.NullString
		nsVersionFormat sql.NullString
	)

	t := time.Now()
	err := pgSQL.QueryRow(searchLayer, name).Scan(
		&layer.ID,
		&layer.Name,
		&layer.EngineVersion,
		&parentID,
		&parentName,
	)
	observeQueryTime("FindLayer", "searchLayer", t)

	if err != nil {
		return layer, handleError("searchLayer", err)
	}

	if !parentID.IsZero() {
		layer.Parent = &database.Layer{
			Model: database.Model{ID: int(parentID.Int64)},
			Name:  parentName.String,
		}
	}

	rows, err := pgSQL.Query(searchLayerNamespace, layer.ID)
	defer rows.Close()
	if err != nil {
		return layer, handleError("searchLayerNamespace", err)
	}
	for rows.Next() {
		err = rows.Scan(&nsID, &nsName, &nsVersionFormat)
		if err != nil {
			return layer, handleError("searchLayerNamespace", err)
		}
		if !nsID.IsZero() {
			layer.Namespaces = append(layer.Namespaces, database.Namespace{
				Model:         database.Model{ID: int(nsID.Int64)},
				Name:          nsName.String,
				VersionFormat: nsVersionFormat.String,
			})
		}
	}

	// Find its features
	if withFeatures || withVulnerabilities {
		// Create a transaction to disable hash/merge joins as our experiments have shown that
		// PostgreSQL 9.4 makes bad planning decisions about:
		// - joining the layer tree to feature versions and feature
		// - joining the feature versions to affected/fixed feature version and vulnerabilities
		// It would for instance do a merge join between affected feature versions (300 rows, estimated
		// 3000 rows) and fixed in feature version (100k rows). In this case, it is much more
		// preferred to use a nested loop.
		tx, err := pgSQL.Begin()
		if err != nil {
			return layer, handleError("FindLayer.Begin()", err)
		}
		defer tx.Commit()

		_, err = tx.Exec(disableHashJoin)
		if err != nil {
			log.WithError(err).Warningf("FindLayer: could not disable hash join")
		}
		_, err = tx.Exec(disableMergeJoin)
		if err != nil {
			log.WithError(err).Warningf("FindLayer: could not disable merge join")
		}

		t = time.Now()
		featureVersions, err := getLayerFeatureVersions(tx, layer.ID)
		observeQueryTime("FindLayer", "getLayerFeatureVersions", t)

		if err != nil {
			return layer, err
		}

		layer.Features = featureVersions

		if withVulnerabilities {
			// Load the vulnerabilities that affect the FeatureVersions.
			t = time.Now()
			err := loadAffectedBy(tx, layer.Features)
			observeQueryTime("FindLayer", "loadAffectedBy", t)

			if err != nil {
				return layer, err
			}
		}
	}

	return layer, nil
}

// getLayerFeatureVersions returns list of database.FeatureVersion that a database.Layer has.
func getLayerFeatureVersions(tx *sql.Tx, layerID int) ([]database.FeatureVersion, error) {
	var featureVersions []database.FeatureVersion

	// Query.
	rows, err := tx.Query(searchLayerFeatureVersion, layerID)
	if err != nil {
		return featureVersions, handleError("searchLayerFeatureVersion", err)
	}
	defer rows.Close()

	// Scan query.
	var modification string
	mapFeatureVersions := make(map[int]database.FeatureVersion)
	for rows.Next() {
		var fv database.FeatureVersion
		err = rows.Scan(
			&fv.ID,
			&modification,
			&fv.Feature.Namespace.ID,
			&fv.Feature.Namespace.Name,
			&fv.Feature.Namespace.VersionFormat,
			&fv.Feature.ID,
			&fv.Feature.Name,
			&fv.ID,
			&fv.Version,
			&fv.AddedBy.ID,
			&fv.AddedBy.Name,
		)
		if err != nil {
			return featureVersions, handleError("searchLayerFeatureVersion.Scan()", err)
		}

		// Do transitive closure.
		switch modification {
		case "add":
			mapFeatureVersions[fv.ID] = fv
		case "del":
			delete(mapFeatureVersions, fv.ID)
		default:
			log.WithField("modification", modification).Warning("unknown Layer_diff_FeatureVersion's modification")
			return featureVersions, database.ErrInconsistent
		}
	}
	if err = rows.Err(); err != nil {
		return featureVersions, handleError("searchLayerFeatureVersion.Rows()", err)
	}

	// Build result by converting our map to a slice.
	for _, featureVersion := range mapFeatureVersions {
		featureVersions = append(featureVersions, featureVersion)
	}

	return featureVersions, nil
}

// loadAffectedBy returns the list of database.Vulnerability that affect the given
// FeatureVersion.
func loadAffectedBy(tx *sql.Tx, featureVersions []database.FeatureVersion) error {
	if len(featureVersions) == 0 {
		return nil
	}

	// Construct list of FeatureVersion IDs, we will do a single query
	featureVersionIDs := make([]int, 0, len(featureVersions))
	for i := 0; i < len(featureVersions); i++ {
		featureVersionIDs = append(featureVersionIDs, featureVersions[i].ID)
	}

	rows, err := tx.Query(searchFeatureVersionVulnerability,
		buildInputArray(featureVersionIDs))
	if err != nil && err != sql.ErrNoRows {
		return handleError("searchFeatureVersionVulnerability", err)
	}
	defer rows.Close()

	vulnerabilities := make(map[int][]database.Vulnerability, len(featureVersions))
	var featureversionID int
	for rows.Next() {
		var vulnerability database.Vulnerability
		err := rows.Scan(
			&featureversionID,
			&vulnerability.ID,
			&vulnerability.Name,
			&vulnerability.Description,
			&vulnerability.Link,
			&vulnerability.Severity,
			&vulnerability.Metadata,
			&vulnerability.Namespace.Name,
			&vulnerability.Namespace.VersionFormat,
			&vulnerability.FixedBy,
		)
		if err != nil {
			return handleError("searchFeatureVersionVulnerability.Scan()", err)
		}
		vulnerabilities[featureversionID] = append(vulnerabilities[featureversionID], vulnerability)
	}
	if err = rows.Err(); err != nil {
		return handleError("searchFeatureVersionVulnerability.Rows()", err)
	}

	// Assign vulnerabilities to every FeatureVersions
	for i := 0; i < len(featureVersions); i++ {
		featureVersions[i].AffectedBy = vulnerabilities[featureVersions[i].ID]
	}

	return nil
}

// Internally, only Feature additions/removals are stored for each layer. If a layer has a parent,
// the Feature list will be compared to the parent's Feature list and the difference will be stored.
// Note that when the Namespace of a layer differs from its parent, it is expected that several
// Feature that were already included a parent will have their Namespace updated as well
// (happens when Feature detectors relies on the detected layer Namespace). However, if the listed
// Feature has the same Name/Version as its parent, InsertLayer considers that the Feature hasn't
// been modified.
func (pgSQL *pgSQL) InsertLayer(layer database.Layer) error {
	tf := time.Now()

	// Verify parameters
	if layer.Name == "" {
		log.Warning("could not insert a layer which has an empty Name")
		return commonerr.NewBadRequestError("could not insert a layer which has an empty Name")
	}

	// Get a potentially existing layer.
	existingLayer, err := pgSQL.FindLayer(layer.Name, true, false)
	if err != nil && err != commonerr.ErrNotFound {
		return err
	} else if err == nil {
		if existingLayer.EngineVersion >= layer.EngineVersion {
			// The layer exists and has an equal or higher engine version, do nothing.
			return nil
		}

		layer.ID = existingLayer.ID
	}

	// We do `defer observeQueryTime` here because we don't want to observe existing layers.
	defer observeQueryTime("InsertLayer", "all", tf)

	// Get parent ID.
	var parentID zero.Int
	if layer.Parent != nil {
		if layer.Parent.ID == 0 {
			log.Warning("Parent is expected to be retrieved from database when inserting a layer.")
			return commonerr.NewBadRequestError("Parent is expected to be retrieved from database when inserting a layer.")
		}

		parentID = zero.IntFrom(int64(layer.Parent.ID))
	}

	// namespaceIDs will contain inherited and new namespaces
	namespaceIDs := make(map[int]struct{})

	// try to insert the new namespaces
	for _, ns := range layer.Namespaces {
		n, err := pgSQL.insertNamespace(ns)
		if err != nil {
			return handleError("pgSQL.insertNamespace", err)
		}
		namespaceIDs[n] = struct{}{}
	}

	// inherit namespaces from parent layer
	if layer.Parent != nil {
		for _, ns := range layer.Parent.Namespaces {
			namespaceIDs[ns.ID] = struct{}{}
		}
	}

	// Begin transaction.
	tx, err := pgSQL.Begin()
	if err != nil {
		tx.Rollback()
		return handleError("InsertLayer.Begin()", err)
	}

	if layer.ID == 0 {
		// Insert a new layer.
		err = tx.QueryRow(insertLayer, layer.Name, layer.EngineVersion, parentID).
			Scan(&layer.ID)
		if err != nil {
			tx.Rollback()

			if isErrUniqueViolation(err) {
				// Ignore this error, another process collided.
				log.Debug("Attempted to insert duplicate layer.")
				return nil
			}
			return handleError("insertLayer", err)
		}
	} else {
		// Update an existing layer.
		_, err = tx.Exec(updateLayer, layer.ID, layer.EngineVersion)
		if err != nil {
			tx.Rollback()
			return handleError("updateLayer", err)
		}

		// replace the old namespace in the database
		_, err := tx.Exec(removeLayerNamespace, layer.ID)
		if err != nil {
			tx.Rollback()
			return handleError("removeLayerNamespace", err)
		}
		// Remove all existing Layer_diff_FeatureVersion.
		_, err = tx.Exec(removeLayerDiffFeatureVersion, layer.ID)
		if err != nil {
			tx.Rollback()
			return handleError("removeLayerDiffFeatureVersion", err)
		}
	}

	// insert the layer's namespaces
	stmt, err := tx.Prepare(insertLayerNamespace)

	if err != nil {
		tx.Rollback()
		return handleError("failed to prepare statement", err)
	}

	defer func() {
		err = stmt.Close()
		if err != nil {
			tx.Rollback()
			log.WithError(err).Error("failed to close prepared statement")
		}
	}()

	for nsid := range namespaceIDs {
		_, err := stmt.Exec(layer.ID, nsid)
		if err != nil {
			tx.Rollback()
			return handleError("insertLayerNamespace", err)
		}
	}

	// Update Layer_diff_FeatureVersion now.
	err = pgSQL.updateDiffFeatureVersions(tx, &layer, &existingLayer)
	if err != nil {
		tx.Rollback()
		return err
	}

	// Commit transaction.
	err = tx.Commit()
	if err != nil {
		tx.Rollback()
		return handleError("InsertLayer.Commit()", err)
	}

	return nil
}

func (pgSQL *pgSQL) updateDiffFeatureVersions(tx *sql.Tx, layer, existingLayer *database.Layer) error {
	// add and del are the FeatureVersion diff we should insert.
	var add []database.FeatureVersion
	var del []database.FeatureVersion

	if layer.Parent == nil {
		// There is no parent, every Features are added.
		add = append(add, layer.Features...)
	} else if layer.Parent != nil {
		// There is a parent, we need to diff the Features with it.

		// Build name:version structures.
		layerFeaturesMapNV, layerFeaturesNV := createNV(layer.Features)
		parentLayerFeaturesMapNV, parentLayerFeaturesNV := createNV(layer.Parent.Features)

		// Calculate the added and deleted FeatureVersions name:version.
		addNV := compareStringLists(layerFeaturesNV, parentLayerFeaturesNV)
		delNV := compareStringLists(parentLayerFeaturesNV, layerFeaturesNV)

		// Fill the structures containing the added and deleted FeatureVersions.
		for _, nv := range addNV {
			add = append(add, *layerFeaturesMapNV[nv])
		}
		for _, nv := range delNV {
			del = append(del, *parentLayerFeaturesMapNV[nv])
		}
	}

	// Insert FeatureVersions in the database.
	addIDs, err := pgSQL.insertFeatureVersions(add)
	if err != nil {
		return err
	}
	delIDs, err := pgSQL.insertFeatureVersions(del)
	if err != nil {
		return err
	}

	// Insert diff in the database.
	if len(addIDs) > 0 {
		_, err = tx.Exec(insertLayerDiffFeatureVersion, layer.ID, "add", buildInputArray(addIDs))
		if err != nil {
			return handleError("insertLayerDiffFeatureVersion.Add", err)
		}
	}
	if len(delIDs) > 0 {
		_, err = tx.Exec(insertLayerDiffFeatureVersion, layer.ID, "del", buildInputArray(delIDs))
		if err != nil {
			return handleError("insertLayerDiffFeatureVersion.Del", err)
		}
	}

	return nil
}

func createNV(features []database.FeatureVersion) (map[string]*database.FeatureVersion, []string) {
	mapNV := make(map[string]*database.FeatureVersion, 0)
	sliceNV := make([]string, 0, len(features))

	for i := 0; i < len(features); i++ {
		fv := &features[i]
		nv := strings.Join([]string{fv.Feature.Namespace.Name, fv.Feature.Name, fv.Version}, ":")
		mapNV[nv] = fv
		sliceNV = append(sliceNV, nv)
	}

	return mapNV, sliceNV
}

func (pgSQL *pgSQL) DeleteLayer(name string) error {
	defer observeQueryTime("DeleteLayer", "all", time.Now())

	result, err := pgSQL.Exec(removeLayer, name)
	if err != nil {
		return handleError("removeLayer", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return handleError("removeLayer.RowsAffected()", err)
	}

	if affected <= 0 {
		return commonerr.ErrNotFound
	}

	return nil
}
