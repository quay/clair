package pgsql

import (
	"fmt"
	"os"
	"path"
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
		fixturePath = path.Join(path.Dir(filename)) + "/testdata/data.sql"
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
