// Copyright 2019 clair authors
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

package ancestry

import (
	"database/sql"
	"errors"

	log "github.com/sirupsen/logrus"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/database/pgsql/detector"
	"github.com/coreos/clair/database/pgsql/layer"
	"github.com/coreos/clair/database/pgsql/util"
)

const (
	insertAncestry = `
		INSERT INTO ancestry (name) VALUES ($1) RETURNING id`

	findAncestryID = `SELECT id FROM ancestry WHERE name = $1`
	removeAncestry = `DELETE FROM ancestry WHERE name = $1`

	insertAncestryFeatures = `
		INSERT INTO ancestry_feature
		(ancestry_layer_id, namespaced_feature_id, feature_detector_id, namespace_detector_id) VALUES
		($1, $2, $3, $4)`
)

func FindAncestry(tx *sql.Tx, name string) (database.Ancestry, bool, error) {
	var (
		ancestry = database.Ancestry{Name: name}
		err      error
	)

	id, ok, err := FindAncestryID(tx, name)
	if !ok || err != nil {
		return ancestry, ok, err
	}

	if ancestry.By, err = FindAncestryDetectors(tx, id); err != nil {
		return ancestry, false, err
	}

	if ancestry.Layers, err = FindAncestryLayers(tx, id); err != nil {
		return ancestry, false, err
	}

	return ancestry, true, nil
}

func UpsertAncestry(tx *sql.Tx, ancestry database.Ancestry) error {
	if !ancestry.Valid() {
		return database.ErrInvalidParameters
	}

	if err := RemoveAncestry(tx, ancestry.Name); err != nil {
		return err
	}

	id, err := InsertAncestry(tx, ancestry.Name)
	if err != nil {
		return err
	}

	detectorIDs, err := detector.FindDetectorIDs(tx, ancestry.By)
	if err != nil {
		return err
	}

	// insert ancestry metadata
	if err := InsertAncestryDetectors(tx, id, detectorIDs); err != nil {
		return err
	}

	layers := make([]string, 0, len(ancestry.Layers))
	for _, l := range ancestry.Layers {
		layers = append(layers, l.Hash)
	}

	layerIDs, ok, err := layer.FindLayerIDs(tx, layers)
	if err != nil {
		return err
	}

	if !ok {
		log.Error("layer cannot be found, this indicates that the internal logic of calling UpsertAncestry is wrong or the database is corrupted.")
		return database.ErrMissingEntities
	}

	ancestryLayerIDs, err := InsertAncestryLayers(tx, id, layerIDs)
	if err != nil {
		return err
	}

	for i, id := range ancestryLayerIDs {
		if err := InsertAncestryFeatures(tx, id, ancestry.Layers[i]); err != nil {
			return err
		}
	}

	return nil
}

func InsertAncestry(tx *sql.Tx, name string) (int64, error) {
	var id int64
	err := tx.QueryRow(insertAncestry, name).Scan(&id)
	if err != nil {
		if util.IsErrUniqueViolation(err) {
			return 0, util.HandleError("insertAncestry", errors.New("other Go-routine is processing this ancestry (skip)"))
		}

		return 0, util.HandleError("insertAncestry", err)
	}

	return id, nil
}

func FindAncestryID(tx *sql.Tx, name string) (int64, bool, error) {
	var id sql.NullInt64
	if err := tx.QueryRow(findAncestryID, name).Scan(&id); err != nil {
		if err == sql.ErrNoRows {
			return 0, false, nil
		}

		return 0, false, util.HandleError("findAncestryID", err)
	}

	return id.Int64, true, nil
}

func RemoveAncestry(tx *sql.Tx, name string) error {
	result, err := tx.Exec(removeAncestry, name)
	if err != nil {
		return util.HandleError("removeAncestry", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return util.HandleError("removeAncestry", err)
	}

	if affected != 0 {
		log.WithField("ancestry", name).Debug("removed ancestry")
	}

	return nil
}
