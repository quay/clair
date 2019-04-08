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

package layer

import (
	"database/sql"

	"github.com/deckarep/golang-set"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/database/pgsql/detector"
	"github.com/coreos/clair/database/pgsql/util"
	"github.com/coreos/clair/pkg/commonerr"
)

const (
	soiLayer = `
		WITH new_layer AS (
			INSERT INTO layer (hash)
			SELECT CAST ($1 AS VARCHAR)
			WHERE NOT EXISTS (SELECT id FROM layer WHERE hash = $1)
			RETURNING id
		)
		SELECT id FROM new_Layer
		UNION
		SELECT id FROM layer WHERE hash = $1`

	findLayerID = `SELECT id FROM layer WHERE hash = $1`
)

func FindLayer(tx *sql.Tx, hash string) (database.Layer, bool, error) {
	layer := database.Layer{Hash: hash}
	if hash == "" {
		return layer, false, commonerr.NewBadRequestError("non empty layer hash is expected.")
	}

	layerID, ok, err := FindLayerID(tx, hash)
	if err != nil || !ok {
		return layer, ok, err
	}

	detectorMap, err := detector.FindAllDetectors(tx)
	if err != nil {
		return layer, false, err
	}

	if layer.By, err = FindLayerDetectors(tx, layerID); err != nil {
		return layer, false, err
	}

	if layer.Features, err = FindLayerFeatures(tx, layerID, detectorMap); err != nil {
		return layer, false, err
	}

	if layer.Namespaces, err = FindLayerNamespaces(tx, layerID, detectorMap); err != nil {
		return layer, false, err
	}

	return layer, true, nil
}

func sanitizePersistLayerInput(hash string, features []database.LayerFeature, namespaces []database.LayerNamespace, detectedBy []database.Detector) error {
	if hash == "" {
		return commonerr.NewBadRequestError("expected non-empty layer hash")
	}

	detectedBySet := mapset.NewSet()
	for _, d := range detectedBy {
		detectedBySet.Add(d)
	}

	for _, f := range features {
		if !detectedBySet.Contains(f.By) {
			return database.ErrInvalidParameters
		}
	}

	for _, n := range namespaces {
		if !detectedBySet.Contains(n.By) {
			return database.ErrInvalidParameters
		}
	}

	return nil
}

// PersistLayer saves the content of a layer to the database.
func PersistLayer(tx *sql.Tx, hash string, features []database.LayerFeature, namespaces []database.LayerNamespace, detectedBy []database.Detector) error {
	var (
		err         error
		id          int64
		detectorIDs []int64
	)

	if err = sanitizePersistLayerInput(hash, features, namespaces, detectedBy); err != nil {
		return err
	}

	if id, err = SoiLayer(tx, hash); err != nil {
		return err
	}

	if detectorIDs, err = detector.FindDetectorIDs(tx, detectedBy); err != nil {
		if err == commonerr.ErrNotFound {
			return database.ErrMissingEntities
		}

		return err
	}

	if err = PersistLayerDetectors(tx, id, detectorIDs); err != nil {
		return err
	}

	if err = PersistAllLayerFeatures(tx, id, features); err != nil {
		return err
	}

	if err = PersistAllLayerNamespaces(tx, id, namespaces); err != nil {
		return err
	}

	return nil
}

func FindLayerID(tx *sql.Tx, hash string) (int64, bool, error) {
	var layerID int64
	err := tx.QueryRow(findLayerID, hash).Scan(&layerID)
	if err != nil {
		if err == sql.ErrNoRows {
			return layerID, false, nil
		}

		return layerID, false, util.HandleError("findLayerID", err)
	}

	return layerID, true, nil
}

func FindLayerIDs(tx *sql.Tx, hashes []string) ([]int64, bool, error) {
	layerIDs := make([]int64, 0, len(hashes))
	for _, hash := range hashes {
		id, ok, err := FindLayerID(tx, hash)
		if !ok {
			return nil, false, nil
		}

		if err != nil {
			return nil, false, err
		}

		layerIDs = append(layerIDs, id)
	}

	return layerIDs, true, nil
}

func SoiLayer(tx *sql.Tx, hash string) (int64, error) {
	var id int64
	if err := tx.QueryRow(soiLayer, hash).Scan(&id); err != nil {
		return 0, util.HandleError("soiLayer", err)
	}

	return id, nil
}
