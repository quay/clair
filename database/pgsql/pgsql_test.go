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

package pgsql

import (
	"database/sql"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	fernet "github.com/fernet/fernet-go"
	"github.com/pborman/uuid"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	yaml "gopkg.in/yaml.v2"

	"github.com/coreos/clair/database"
)

var (
	withFixtureName, withoutFixtureName string
)

func genTemplateDatabase(name string, loadFixture bool) (sourceURL string, dbName string) {
	config := generateTestConfig(name, loadFixture, false)
	source := config.Options["source"].(string)
	name, url, err := parseConnectionString(source)
	if err != nil {
		panic(err)
	}

	fixturePath := config.Options["fixturepath"].(string)

	if err := createDatabase(url, name); err != nil {
		panic(err)
	}

	// migration and fixture
	db, err := sql.Open("postgres", source)
	if err != nil {
		panic(err)
	}

	// Verify database state.
	if err := db.Ping(); err != nil {
		panic(err)
	}

	// Run migrations.
	if err := migrateDatabase(db); err != nil {
		panic(err)
	}

	if loadFixture {
		log.Info("pgsql: loading fixtures")

		d, err := ioutil.ReadFile(fixturePath)
		if err != nil {
			panic(err)
		}

		_, err = db.Exec(string(d))
		if err != nil {
			panic(err)
		}
	}

	db.Exec("UPDATE pg_database SET datistemplate=True WHERE datname=$1", name)
	db.Close()

	log.Info("Generated Template database ", name)
	return url, name
}

func dropTemplateDatabase(url string, name string) {
	db, err := sql.Open("postgres", url)
	if err != nil {
		panic(err)
	}

	if _, err := db.Exec("UPDATE pg_database SET datistemplate=False WHERE datname=$1", name); err != nil {
		panic(err)
	}

	if err := db.Close(); err != nil {
		panic(err)
	}

	if err := dropDatabase(url, name); err != nil {
		panic(err)
	}

}
func TestMain(m *testing.M) {
	fURL, fName := genTemplateDatabase("fixture", true)
	nfURL, nfName := genTemplateDatabase("nonfixture", false)

	withFixtureName = fName
	withoutFixtureName = nfName

	m.Run()

	dropTemplateDatabase(fURL, fName)
	dropTemplateDatabase(nfURL, nfName)
}

func openCopiedDatabase(testConfig database.RegistrableComponentConfig, fixture bool) (database.Datastore, error) {
	var fixtureName string
	if fixture {
		fixtureName = withFixtureName
	} else {
		fixtureName = withoutFixtureName
	}

	// copy the database into new database
	var pg pgSQL
	// Parse configuration.
	pg.config = Config{
		CacheSize: 16384,
	}

	bytes, err := yaml.Marshal(testConfig.Options)
	if err != nil {
		return nil, fmt.Errorf("pgsql: could not load configuration: %v", err)
	}
	err = yaml.Unmarshal(bytes, &pg.config)
	if err != nil {
		return nil, fmt.Errorf("pgsql: could not load configuration: %v", err)
	}

	dbName, pgSourceURL, err := parseConnectionString(pg.config.Source)
	if err != nil {
		return nil, err
	}

	// Create database.
	if pg.config.ManageDatabaseLifecycle {
		if err = copyDatabase(pgSourceURL, dbName, fixtureName); err != nil {
			return nil, err
		}
	}

	// Open database.
	pg.DB, err = sql.Open("postgres", pg.config.Source)
	fmt.Println("database", pg.config.Source)
	if err != nil {
		pg.Close()
		return nil, fmt.Errorf("pgsql: could not open database: %v", err)
	}

	return &pg, nil
}

// copyDatabase creates a new database with
func copyDatabase(url, name string, templateName string) error {
	// Open database.
	db, err := sql.Open("postgres", url)
	if err != nil {
		return fmt.Errorf("pgsql: could not open 'postgres' database for creation: %v", err)
	}
	defer db.Close()

	// Create database with copy
	_, err = db.Exec("CREATE DATABASE " + name + " WITH TEMPLATE " + templateName)
	if err != nil {
		return fmt.Errorf("pgsql: could not create database: %v", err)
	}

	return nil
}

func openDatabaseForTest(testName string, loadFixture bool) (*pgSQL, error) {
	var (
		db         database.Datastore
		err        error
		testConfig = generateTestConfig(testName, loadFixture, true)
	)

	db, err = openCopiedDatabase(testConfig, loadFixture)

	if err != nil {
		return nil, err
	}
	datastore := db.(*pgSQL)
	return datastore, nil
}

func generateTestConfig(testName string, loadFixture bool, manageLife bool) database.RegistrableComponentConfig {
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

	var key fernet.Key
	if err := key.Generate(); err != nil {
		panic("failed to generate pagination key" + err.Error())
	}

	return database.RegistrableComponentConfig{
		Options: map[string]interface{}{
			"source":                  source,
			"cachesize":               0,
			"managedatabaselifecycle": manageLife,
			"fixturepath":             fixturePath,
			"paginationkey":           key.Encode(),
		},
	}
}

func closeTest(t *testing.T, store database.Datastore, session database.Session) {
	err := session.Rollback()
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	store.Close()
}

func openSessionForTest(t *testing.T, name string, loadFixture bool) (*pgSQL, *pgSession) {
	store, err := openDatabaseForTest(name, loadFixture)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	tx, err := store.Begin()
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	return store, tx.(*pgSession)
}

func restartSession(t *testing.T, datastore *pgSQL, tx *pgSession, commit bool) *pgSession {
	var err error
	if !commit {
		err = tx.Rollback()
	} else {
		err = tx.Commit()
	}

	if assert.Nil(t, err) {
		session, err := datastore.Begin()
		if assert.Nil(t, err) {
			return session.(*pgSession)
		}
	}
	t.FailNow()
	return nil
}
