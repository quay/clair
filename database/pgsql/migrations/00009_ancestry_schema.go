// Copyright 2016 clair authors
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

package migrations

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/guregu/null/zero"
	lru "github.com/hashicorp/golang-lru"
	"github.com/lib/pq"
	"github.com/remind101/migrate"
	"github.com/sirupsen/logrus"
)

// on error, the function will rollback every migration changes in database.
func up(tx *sql.Tx) error {
	err := migrate.Queries([]string{
		`CREATE TABLE IF NOT EXISTS ancestry (
			id SERIAL PRIMARY KEY,
			name VARCHAR(128) NOT NULL,
			engineversion INT NOT NULL,
			unique(name, engineversion)
			)`,
		`INSERT INTO ancestry(name, engineversion) SELECT name, engineversion FROM layer`,
		`CREATE TABLE IF NOT EXISTS layer_ancestry(
				id SERIAL PRIMARY KEY,
				hash VARCHAR(128) NOT NULL,
				ancestry_id INT NOT NULL,
				ancestry_index INT NOT NULL,
				unique(ancestry_id, ancestry_index)
				)`,
		`CREATE INDEX ON ancestry(name)`,
		`CREATE INDEX ON layer_ancestry(ancestry_id)`,
		`CREATE INDEX ON layer_ancestry(hash)`,
	})(tx)
	countLayerNum := `SELECT count(id) FROM layer`
	selectLayer := `
	SELECT layer.name, layer.id, parent_id, ancestry.id, layer.engineversion
		FROM layer, ancestry 
		WHERE ancestry.name = layer.name 
			  AND layer.id >= $1 
		ORDER BY layer.id LIMIT $2`

	selectAncestry := `
	SELECT layer_ancestry.hash, layer.engineversion
		FROM ancestry, layer_ancestry, layer
		WHERE layer.id = $1
			AND ancestry.name = layer.name
			AND layer_ancestry.ancestry_id = ancestry.id
		ORDER BY layer_ancestry.ancestry_index`

	if err != nil {
		return err
	}
	totalCount := 0
	count := 0
	err = tx.QueryRow(countLayerNum).Scan(&totalCount)
	if err != nil {
		return err
	}
	logrus.Debugf("processing %d layers", totalCount)
	batchSize := 9600
	nextID := 0
	cache := newCache(960000)

	// until no layer is selected from database
	for {
		// for statistics
		cachehit := 0
		startBatch := time.Now()

		rows, err := tx.Query(selectLayer, nextID, batchSize)
		if err != nil {
			return err
		}

		// query a batch of layers to compute ancestries
		var (
			layerBatch = make([]layerBuffer, 0, batchSize)
		)

		startLayerSel := time.Now()
		for rows.Next() {
			layer := layerBuffer{}
			err = rows.Scan(&layer.hash, &layer.id, &layer.parentID, &layer.ancestryID, &layer.engineversion)
			if err != nil {
				rows.Close()
				return err
			}

			// the migration is based on assumption that a layer's parent id
			// should be less than the layer's id
			if layer.parentID.Valid && int(layer.parentID.Int64) > layer.id {
				rows.Close()
				return errors.New("unsupported in migration: layer id > layer's parent id")
			}
			layerBatch = append(layerBatch, layer)
		}

		err = rows.Close()
		if err != nil {
			return err
		}

		count += len(layerBatch)
		if len(layerBatch) == 0 {
			break
		} else {
			// set next layer batch's starting id
			nextID = layerBatch[len(layerBatch)-1].id + 1
		}
		layerSelCost := time.Since(startLayerSel)

		ancestrySel := time.Now()
		// construct ancestries for every layer
		ancestryBatch := []ancestryBuffer{}
		for _, layer := range layerBatch {
			var (
				ancestry           ancestryBuffer
				incache            bool
				layerHash          string
				layerEngineversion int
			)

			if layer.parentID.Valid {
				if ancestry, incache = cache.get(int(layer.parentID.Int64)); !incache {
					ancestryRows, err := tx.Query(selectAncestry, layer.parentID.Int64)

					if err != nil {
						rows.Close()
						return err
					}

					for ancestryRows.Next() {
						err := ancestryRows.Scan(&layerHash, &layerEngineversion)
						if err != nil {
							rows.Close()
							ancestryRows.Close()
							return err
						}

						// enforce every layer to have the same
						// engineversion in an ancestry
						if layerEngineversion != layer.engineversion {
							rows.Close()
							ancestryRows.Close()
							return errors.New("Ancestry engineversion mismatch")
						}

						ancestry.layers = append(ancestry.layers, layerHash)
					}

					ancestryRows.Close()
					ancestry.layers = ancestry.layers[:]
					cache.add(int(layer.parentID.Int64), ancestry)
				} else {
					cachehit++
				}
			}
			ancestry.id = layer.ancestryID
			ancestry.layers = append(ancestry.layers, layer.hash)
			cache.add(layer.id, ancestry)
			ancestryBatch = append(ancestryBatch, ancestry)
		}
		ancestrySelCost := time.Since(ancestrySel)
		ancestryIns := time.Now()
		// batch insert ancestries
		insertAncestry, err := tx.Prepare(pq.CopyIn("layer_ancestry", "hash", "ancestry_id", "ancestry_index"))
		if err != nil {
			return err
		}

		for _, ancestry := range ancestryBatch {
			for i, layerHash := range ancestry.layers {
				_, err := insertAncestry.Exec(layerHash, ancestry.id, i)
				if err != nil {
					insertAncestry.Close()
					return err
				}
			}
		}

		_, err = insertAncestry.Exec()
		if err != nil {
			insertAncestry.Close()
			return err
		}

		err = insertAncestry.Close()
		if err != nil {
			return err
		}
		ancestryInsCost := time.Since(ancestryIns)
		logrus.WithFields(logrus.Fields{
			"progress":     fmt.Sprintf("%f%%(%d/%d)", 100*float32(count)/float32(totalCount), count, totalCount),
			"layer sel":    fmt.Sprintf("%v", layerSelCost),
			"ancestry sel": fmt.Sprintf("%v", ancestrySelCost),
			"ancestry ins": fmt.Sprintf("%v", ancestryInsCost),
			"total cost":   fmt.Sprint(time.Since(startBatch)),
			"cache hit":    fmt.Sprintf("%f%%", 100*float32(cachehit)/float32(len(ancestryBatch))),
		}).Debugln("finished ancestry")
	}

	err = migrate.Queries([]string{
		`ALTER TABLE layer_ancestry
			ADD CONSTRAINT layer_ancestry_ancestry_id_fkey
			FOREIGN KEY (ancestry_id)
			REFERENCES ancestry
			ON DELETE CASCADE`,
	})(tx)
	if err != nil {
		return err
	}
	return nil
}

func newCache(size int) ancestryCache {
	cache, err := lru.NewARC(size)
	if err != nil {
		return nil
	}
	return &arcCache{lru: cache}
}

type layerBuffer struct {
	id            int
	hash          string
	parentID      zero.Int
	ancestryID    int
	engineversion int
}

type ancestryBuffer struct {
	id     int
	layers []string
}

type ancestryCache interface {
	add(id int, ancestry ancestryBuffer)
	get(id int) (ancestryBuffer, bool)
}

type arcCache struct {
	lru *lru.ARCCache
}

func (c *arcCache) add(layerID int, ancestry ancestryBuffer) {
	c.lru.Add(layerID, ancestry)
}

func (c *arcCache) get(layerID int) (ancestryBuffer, bool) {
	v, ok := c.lru.Get(layerID)
	if !ok {
		return ancestryBuffer{}, ok
	}
	r, ok := v.(ancestryBuffer)
	if !ok {
		panic("invalid cache")
	}
	return r, ok
}

func init() {
	RegisterMigration(migrate.Migration{
		ID: 9,
		Up: up,
		Down: migrate.Queries([]string{
			`DROP TABLE IF EXISTS layer_ancestry`,
			`DROP TABLE IF EXISTS ancestry`,
		}),
	})
}
