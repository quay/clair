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

package keyvalue

import (
	"database/sql"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/coreos/clair/database/pgsql/monitoring"
	"github.com/coreos/clair/database/pgsql/util"
	"github.com/coreos/clair/pkg/commonerr"
)

const (
	searchKeyValue = `SELECT value FROM KeyValue WHERE key = $1`
	upsertKeyValue = `
			INSERT INTO KeyValue(key, value) 
				VALUES ($1, $2) 
				ON CONFLICT ON CONSTRAINT keyvalue_key_key 
				DO UPDATE SET key=$1, value=$2`
)

func UpdateKeyValue(tx *sql.Tx, key, value string) (err error) {
	if key == "" || value == "" {
		log.Warning("could not insert a flag which has an empty name or value")
		return commonerr.NewBadRequestError("could not insert a flag which has an empty name or value")
	}

	defer monitoring.ObserveQueryTime("PersistKeyValue", "all", time.Now())

	_, err = tx.Exec(upsertKeyValue, key, value)
	if err != nil {
		return util.HandleError("insertKeyValue", err)
	}

	return nil
}

func FindKeyValue(tx *sql.Tx, key string) (string, bool, error) {
	defer monitoring.ObserveQueryTime("FindKeyValue", "all", time.Now())

	var value string
	err := tx.QueryRow(searchKeyValue, key).Scan(&value)

	if err == sql.ErrNoRows {
		return "", false, nil
	}

	if err != nil {
		return "", false, util.HandleError("searchKeyValue", err)
	}

	return value, true, nil
}
