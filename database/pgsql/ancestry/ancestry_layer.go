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

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/database/pgsql/detector"
	"github.com/coreos/clair/database/pgsql/util"
	"github.com/coreos/clair/pkg/commonerr"
	log "github.com/sirupsen/logrus"
)

const (
	findAncestryLayerHashes = `
	SELECT layer.hash, ancestry_layer.ancestry_index
	FROM layer, ancestry_layer
	WHERE ancestry_layer.ancestry_id = $1
		AND ancestry_layer.layer_id = layer.id
	ORDER BY ancestry_layer.ancestry_index ASC`
	insertAncestryLayers = `
	INSERT INTO ancestry_layer (ancestry_id, ancestry_index, layer_id) VALUES ($1, $2, $3)
	RETURNING id`
)

func FindAncestryLayerHashes(tx *sql.Tx, ancestryID int64) (map[int64]string, error) {
	// retrieve layer indexes and hashes
	rows, err := tx.Query(findAncestryLayerHashes, ancestryID)
	if err != nil {
		return nil, util.HandleError("findAncestryLayerHashes", err)
	}

	layerHashes := map[int64]string{}
	for rows.Next() {
		var (
			hash  string
			index int64
		)

		if err = rows.Scan(&hash, &index); err != nil {
			return nil, util.HandleError("findAncestryLayerHashes", err)
		}

		if _, ok := layerHashes[index]; ok {
			// one ancestry index should correspond to only one layer
			return nil, database.ErrInconsistent
		}

		layerHashes[index] = hash
	}

	return layerHashes, nil
}

// insertAncestryLayers inserts the ancestry layers along with its content into
// the database. The layers are 0 based indexed in the original order.
func InsertAncestryLayers(tx *sql.Tx, ancestryID int64, layers []int64) ([]int64, error) {
	stmt, err := tx.Prepare(insertAncestryLayers)
	if err != nil {
		return nil, util.HandleError("insertAncestryLayers", err)
	}

	ancestryLayerIDs := []int64{}
	for index, layerID := range layers {
		var ancestryLayerID sql.NullInt64
		if err := stmt.QueryRow(ancestryID, index, layerID).Scan(&ancestryLayerID); err != nil {
			return nil, util.HandleError("insertAncestryLayers", commonerr.CombineErrors(err, stmt.Close()))
		}

		if !ancestryLayerID.Valid {
			return nil, database.ErrInconsistent
		}

		ancestryLayerIDs = append(ancestryLayerIDs, ancestryLayerID.Int64)
	}

	if err := stmt.Close(); err != nil {
		return nil, util.HandleError("insertAncestryLayers", err)
	}

	return ancestryLayerIDs, nil
}

func FindAncestryLayers(tx *sql.Tx, id int64) ([]database.AncestryLayer, error) {
	detectors, err := detector.FindAllDetectors(tx)
	if err != nil {
		return nil, err
	}

	layerMap, err := FindAncestryLayerHashes(tx, id)
	if err != nil {
		return nil, err
	}

	featureMap, err := FindAncestryFeatures(tx, id, detectors)
	if err != nil {
		return nil, err
	}

	layers := make([]database.AncestryLayer, len(layerMap))
	for index, layer := range layerMap {
		// index MUST match the ancestry layer slice index.
		if layers[index].Hash == "" && len(layers[index].Features) == 0 {
			layers[index] = database.AncestryLayer{
				Hash:     layer,
				Features: featureMap[index],
			}
		} else {
			log.WithFields(log.Fields{
				"ancestry ID":               id,
				"duplicated ancestry index": index,
			}).WithError(database.ErrInconsistent).Error("ancestry layers with same ancestry_index is not allowed")
			return nil, database.ErrInconsistent
		}
	}

	return layers, nil
}
