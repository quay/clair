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

package pgsql

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/coreos/clair/database/pgsql/namespace"
	"github.com/coreos/clair/database/pgsql/testutil"
)

const (
	numVulnerabilities = 100
	numFeatures        = 100
)

func TestConcurrency(t *testing.T) {
	db, cleanup := testutil.CreateTestDB(t, "concurrency")
	defer cleanup()

	var wg sync.WaitGroup
	// there's a limit on the number of concurrent connections in the pool
	wg.Add(30)
	for i := 0; i < 30; i++ {
		go func() {
			defer wg.Done()
			nsNamespaces := testutil.GenRandomNamespaces(t, 100)
			tx, err := db.Begin()
			if err != nil {
				panic(err)
			}

			assert.Nil(t, namespace.PersistNamespaces(tx, nsNamespaces))
			if err := tx.Commit(); err != nil {
				panic(err)
			}
		}()
	}

	wg.Wait()
}
