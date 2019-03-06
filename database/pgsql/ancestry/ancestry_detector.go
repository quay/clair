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
)

var selectAncestryDetectors = `
SELECT d.name, d.version, d.dtype
	FROM ancestry_detector, detector AS d
	WHERE ancestry_detector.detector_id = d.id AND ancestry_detector.ancestry_id = $1;`

var insertAncestryDetectors = `
	INSERT INTO ancestry_detector (ancestry_id, detector_id)
		SELECT $1, $2
		WHERE NOT EXISTS (SELECT id FROM ancestry_detector WHERE ancestry_id = $1 AND detector_id = $2)`

func FindAncestryDetectors(tx *sql.Tx, id int64) ([]database.Detector, error) {
	detectors, err := detector.GetDetectors(tx, selectAncestryDetectors, id)
	return detectors, err
}

func InsertAncestryDetectors(tx *sql.Tx, ancestryID int64, detectorIDs []int64) error {
	for _, detectorID := range detectorIDs {
		if _, err := tx.Exec(insertAncestryDetectors, ancestryID, detectorID); err != nil {
			return util.HandleError("insertAncestryDetectors", err)
		}
	}

	return nil
}
