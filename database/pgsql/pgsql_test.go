// Copyright 2015 clair authors
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
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/coreos/clair/config"
	"github.com/pborman/uuid"
)

func openDatabaseForTest(testName string, loadFixture bool) (*pgSQL, error) {
	ds, err := openDatabase(generateTestConfig(testName, loadFixture))
	if err != nil {
		return nil, err
	}
	datastore := ds.(*pgSQL)
	return datastore, nil
}

func generateTestConfig(testName string, loadFixture bool) config.RegistrableComponentConfig {
	dbName := "test_" + strings.ToLower(testName) + "_" + strings.Replace(uuid.New(), "-", "_", -1)

	var fixturePath string
	if loadFixture {
		_, filename, _, _ := runtime.Caller(0)
		fixturePath = filepath.Join(filepath.Dir(filename)) + "/testdata/data.sql"
	}

	source := fmt.Sprintf("postgresql://postgres@127.0.0.1:5432/%s?sslmode=disable", dbName)
	if sourceEnv := os.Getenv("CLAIR_TEST_PGSQL"); sourceEnv != "" {
		source = fmt.Sprintf(sourceEnv, dbName)
	}

	return config.RegistrableComponentConfig{
		Options: map[string]interface{}{
			"source":                  source,
			"cachesize":               0,
			"managedatabaselifecycle": true,
			"fixturepath":             fixturePath,
		},
	}
}
