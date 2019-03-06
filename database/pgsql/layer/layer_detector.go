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

package layer

import (
	"database/sql"

	"github.com/deckarep/golang-set"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/database/pgsql/detector"
	"github.com/coreos/clair/database/pgsql/util"
)

const (
	selectLayerDetectors = `
		SELECT d.name, d.version, d.dtype
			FROM layer_detector, detector AS d
			WHERE layer_detector.detector_id = d.id AND layer_detector.layer_id = $1;`

	persistLayerDetector = `
			INSERT INTO layer_detector (layer_id, detector_id)
			SELECT $1, $2
			WHERE NOT EXISTS (SELECT id FROM layer_detector WHERE layer_id = $1 AND detector_id = $2)`
)

func PersistLayerDetector(tx *sql.Tx, layerID int64, detectorID int64) error {
	if _, err := tx.Exec(persistLayerDetector, layerID, detectorID); err != nil {
		return util.HandleError("persistLayerDetector", err)
	}

	return nil
}

func PersistLayerDetectors(tx *sql.Tx, layerID int64, detectorIDs []int64) error {
	alreadySaved := mapset.NewSet()
	for _, id := range detectorIDs {
		if alreadySaved.Contains(id) {
			continue
		}

		alreadySaved.Add(id)
		if err := PersistLayerDetector(tx, layerID, id); err != nil {
			return err
		}
	}

	return nil
}

func FindLayerDetectors(tx *sql.Tx, id int64) ([]database.Detector, error) {
	detectors, err := detector.GetDetectors(tx, selectLayerDetectors, id)
	return detectors, err
}
