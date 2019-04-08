// Copyright 2018 clair authors
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

package detector

import (
	"database/sql"

	log "github.com/sirupsen/logrus"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/database/pgsql/util"
)

const (
	soiDetector = `
		INSERT INTO detector (name, version, dtype)
			SELECT CAST ($1 AS TEXT), CAST ($2 AS TEXT), CAST ($3 AS detector_type )
			WHERE NOT EXISTS (SELECT id FROM detector WHERE name = $1 AND version = $2 AND dtype = $3);`

	findDetectorID   = `SELECT id FROM detector WHERE name = $1 AND version = $2 AND dtype = $3`
	findAllDetectors = `SELECT id, name, version, dtype FROM detector`
)

type DetectorMap struct {
	ByID    map[int64]database.Detector
	ByValue map[database.Detector]int64
}

func PersistDetectors(tx *sql.Tx, detectors []database.Detector) error {
	for _, d := range detectors {
		if !d.Valid() {
			log.WithField("detector", d).Debug("Invalid Detector")
			return database.ErrInvalidParameters
		}

		r, err := tx.Exec(soiDetector, d.Name, d.Version, d.DType)
		if err != nil {
			return util.HandleError("soiDetector", err)
		}

		count, err := r.RowsAffected()
		if err != nil {
			return util.HandleError("soiDetector", err)
		}

		if count == 0 {
			log.Debug("detector already exists: ", d)
		}
	}

	return nil
}

// findDetectorIDs retrieve ids of the detectors from the database, if any is not
// found, return the error.
func FindDetectorIDs(tx *sql.Tx, detectors []database.Detector) ([]int64, error) {
	ids := []int64{}
	for _, d := range detectors {
		id := sql.NullInt64{}
		err := tx.QueryRow(findDetectorID, d.Name, d.Version, d.DType).Scan(&id)
		if err != nil {
			return nil, util.HandleError("findDetectorID", err)
		}

		if !id.Valid {
			return nil, database.ErrInconsistent
		}

		ids = append(ids, id.Int64)
	}

	return ids, nil
}

func GetDetectors(tx *sql.Tx, query string, id int64) ([]database.Detector, error) {
	rows, err := tx.Query(query, id)
	if err != nil {
		return nil, util.HandleError("getDetectors", err)
	}

	detectors := []database.Detector{}
	for rows.Next() {
		d := database.Detector{}
		err := rows.Scan(&d.Name, &d.Version, &d.DType)
		if err != nil {
			return nil, util.HandleError("getDetectors", err)
		}

		if !d.Valid() {
			return nil, database.ErrInvalidDetector
		}

		detectors = append(detectors, d)
	}

	return detectors, nil
}

func FindAllDetectors(tx *sql.Tx) (DetectorMap, error) {
	rows, err := tx.Query(findAllDetectors)
	if err != nil {
		return DetectorMap{}, util.HandleError("searchAllDetectors", err)
	}

	detectors := DetectorMap{ByID: make(map[int64]database.Detector), ByValue: make(map[database.Detector]int64)}
	for rows.Next() {
		var (
			id int64
			d  database.Detector
		)
		if err := rows.Scan(&id, &d.Name, &d.Version, &d.DType); err != nil {
			return DetectorMap{}, util.HandleError("searchAllDetectors", err)
		}

		detectors.ByID[id] = d
		detectors.ByValue[d] = id
	}

	return detectors, nil
}
