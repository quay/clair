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

package pgsql

import (
	"database/sql"

	"github.com/deckarep/golang-set"
	log "github.com/sirupsen/logrus"

	"github.com/coreos/clair/database"
)

const (
	soiDetector = `
		INSERT INTO detector (name, version, dtype)
			SELECT CAST ($1 AS TEXT), CAST ($2 AS TEXT), CAST ($3 AS detector_type )
			WHERE NOT EXISTS (SELECT id FROM detector WHERE name = $1 AND version = $2 AND dtype = $3);`

	selectAncestryDetectors = `
		SELECT d.name, d.version, d.dtype
			FROM ancestry_detector, detector AS d
			WHERE ancestry_detector.detector_id = d.id AND ancestry_detector.ancestry_id = $1;`

	selectLayerDetectors = `
		SELECT d.name, d.version, d.dtype
			FROM layer_detector, detector AS d
			WHERE layer_detector.detector_id = d.id AND layer_detector.layer_id = $1;`

	insertAncestryDetectors = `
		INSERT INTO ancestry_detector (ancestry_id, detector_id)
			SELECT $1, $2
			WHERE NOT EXISTS (SELECT id FROM ancestry_detector WHERE ancestry_id = $1 AND detector_id = $2)`

	persistLayerDetector = `
			INSERT INTO layer_detector (layer_id, detector_id)
			SELECT $1, $2
			WHERE NOT EXISTS (SELECT id FROM layer_detector WHERE layer_id = $1 AND detector_id = $2)`

	findDetectorID   = `SELECT id FROM detector WHERE name = $1 AND version = $2 AND dtype = $3`
	findAllDetectors = `SELECT id, name, version, dtype FROM detector`
)

type detectorMap struct {
	byID    map[int64]database.Detector
	byValue map[database.Detector]int64
}

func (tx *pgSession) PersistDetectors(detectors []database.Detector) error {
	for _, d := range detectors {
		if !d.Valid() {
			log.WithField("detector", d).Debug("Invalid Detector")
			return database.ErrInvalidParameters
		}

		r, err := tx.Exec(soiDetector, d.Name, d.Version, d.DType)
		if err != nil {
			return handleError("soiDetector", err)
		}

		count, err := r.RowsAffected()
		if err != nil {
			return handleError("soiDetector", err)
		}

		if count == 0 {
			log.Debug("detector already exists: ", d)
		}
	}

	return nil
}

func (tx *pgSession) persistLayerDetector(layerID int64, detectorID int64) error {
	if _, err := tx.Exec(persistLayerDetector, layerID, detectorID); err != nil {
		return handleError("persistLayerDetector", err)
	}

	return nil
}

func (tx *pgSession) persistLayerDetectors(layerID int64, detectorIDs []int64) error {
	alreadySaved := mapset.NewSet()
	for _, id := range detectorIDs {
		if alreadySaved.Contains(id) {
			continue
		}

		alreadySaved.Add(id)
		if err := tx.persistLayerDetector(layerID, id); err != nil {
			return err
		}
	}

	return nil
}

func (tx *pgSession) insertAncestryDetectors(ancestryID int64, detectorIDs []int64) error {
	for _, detectorID := range detectorIDs {
		if _, err := tx.Exec(insertAncestryDetectors, ancestryID, detectorID); err != nil {
			return handleError("insertAncestryDetectors", err)
		}
	}

	return nil
}

func (tx *pgSession) findAncestryDetectors(id int64) ([]database.Detector, error) {
	detectors, err := tx.getDetectors(selectAncestryDetectors, id)
	log.WithField("detectors", detectors).Debug("found ancestry detectors")
	return detectors, err
}

func (tx *pgSession) findLayerDetectors(id int64) ([]database.Detector, error) {
	detectors, err := tx.getDetectors(selectLayerDetectors, id)
	log.WithField("detectors", detectors).Debug("found layer detectors")
	return detectors, err
}

// findDetectorIDs retrieve ids of the detectors from the database, if any is not
// found, return the error.
func (tx *pgSession) findDetectorIDs(detectors []database.Detector) ([]int64, error) {
	ids := []int64{}
	for _, d := range detectors {
		id := sql.NullInt64{}
		err := tx.QueryRow(findDetectorID, d.Name, d.Version, d.DType).Scan(&id)
		if err != nil {
			return nil, handleError("findDetectorID", err)
		}

		if !id.Valid {
			return nil, database.ErrInconsistent
		}

		ids = append(ids, id.Int64)
	}

	return ids, nil
}

func (tx *pgSession) getDetectors(query string, id int64) ([]database.Detector, error) {
	rows, err := tx.Query(query, id)
	if err != nil {
		return nil, handleError("getDetectors", err)
	}

	detectors := []database.Detector{}
	for rows.Next() {
		d := database.Detector{}
		err := rows.Scan(&d.Name, &d.Version, &d.DType)
		if err != nil {
			return nil, handleError("getDetectors", err)
		}

		if !d.Valid() {
			return nil, database.ErrInvalidDetector
		}

		detectors = append(detectors, d)
	}

	return detectors, nil
}

func (tx *pgSession) findAllDetectors() (detectorMap, error) {
	rows, err := tx.Query(findAllDetectors)
	if err != nil {
		return detectorMap{}, handleError("searchAllDetectors", err)
	}

	detectors := detectorMap{byID: make(map[int64]database.Detector), byValue: make(map[database.Detector]int64)}
	for rows.Next() {
		var (
			id int64
			d  database.Detector
		)
		if err := rows.Scan(&id, &d.Name, &d.Version, &d.DType); err != nil {
			return detectorMap{}, handleError("searchAllDetectors", err)
		}

		detectors.byID[id] = d
		detectors.byValue[d] = id
	}

	return detectors, nil
}
