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

package util

import (
	"database/sql"
	"strings"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/database/pgsql/monitoring"
	"github.com/coreos/clair/pkg/commonerr"
	"github.com/lib/pq"
	"github.com/sirupsen/logrus"
)

// IsErrUniqueViolation determines is the given error is a unique contraint violation.
func IsErrUniqueViolation(err error) bool {
	pqErr, ok := err.(*pq.Error)
	return ok && pqErr.Code == "23505"
}

// HandleError logs an error with an extra description and masks the error if it's an SQL one.
// The function ensures we never return plain SQL errors and leak anything.
// The function should be used for every database query error.
func HandleError(desc string, err error) error {
	if err == nil {
		return nil
	}

	if err == sql.ErrNoRows {
		return commonerr.ErrNotFound
	}

	if pqErr, ok := err.(*pq.Error); ok {
		if pqErr.Fatal() {
			panic(pqErr)
		}

		if pqErr.Code == "42601" {
			panic("invalid query: " + desc + ", info: " + err.Error())
		}
	}

	logrus.WithError(err).WithField("Description", desc).Error("database: handled database error")
	monitoring.PromErrorsTotal.WithLabelValues(desc).Inc()
	if _, o := err.(*pq.Error); o || err == sql.ErrTxDone || strings.HasPrefix(err.Error(), "sql:") {
		return database.ErrBackendException
	}

	return err
}
