// Copyright 2015 quay-sec authors
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

// Package database implements every database models and the functions that
// manipulate them.
package database

import (
	"errors"
	"os"

	"github.com/barakmich/glog"
	"github.com/coreos/pkg/capnslog"
	"github.com/coreos/quay-sec/health"
	"github.com/coreos/quay-sec/utils"
	"github.com/google/cayley"
	"github.com/google/cayley/graph"
	"github.com/google/cayley/graph/path"

	// Load all supported backends.
	_ "github.com/google/cayley/graph/bolt"
	_ "github.com/google/cayley/graph/leveldb"
	_ "github.com/google/cayley/graph/memstore"
	_ "github.com/google/cayley/graph/mongo"
	_ "github.com/google/cayley/graph/sql"
)

const (
	// FieldIs is the graph predicate defining the type of an entity.
	FieldIs = "is"
)

var (
	log = capnslog.NewPackageLogger("github.com/coreos/quay-sec", "database")

	// ErrTransaction is an error that occurs when a database transaction fails.
	ErrTransaction = errors.New("database: transaction failed (concurrent modification?)")
	// ErrBackendException is an error that occurs when the database backend does
	// not work properly (ie. unreachable).
	ErrBackendException = errors.New("database: could not query backend")
	// ErrInconsistent is an error that occurs when a database consistency check
	// fails (ie. when an entity which is supposed to be unique is detected twice)
	ErrInconsistent = errors.New("database: inconsistent database")
	// ErrCantOpen is an error that occurs when the database could not be opened
	ErrCantOpen = errors.New("database: could not open database")

	store *cayley.Handle
)

func init() {
	health.RegisterHealthchecker("database", Healthcheck)
}

// Open opens a Cayley database, creating it if necessary and return its handle
func Open(dbType, dbPath string) error {
	if store != nil {
		log.Errorf("could not open database at %s : a database is already opened", dbPath)
		return ErrCantOpen
	}

	var err error

	// Try to create database if necessary
	if dbType == "bolt" || dbType == "leveldb" {
		if _, err := os.Stat(dbPath); os.IsNotExist(err) {
			// No, initialize it if possible
			log.Infof("database at %s does not exist yet, creating it", dbPath)

			if err = graph.InitQuadStore(dbType, dbPath, nil); err != nil {
				log.Errorf("could not create database at %s : %s", dbPath, err)
				return ErrCantOpen
			}
		}
	} else if dbType == "sql" {
		graph.InitQuadStore(dbType, dbPath, nil)
	}

	store, err = cayley.NewGraph(dbType, dbPath, nil)
	if err != nil {
		log.Errorf("could not open database at %s : %s", dbPath, err)
		return ErrCantOpen
	}

	return nil
}

// Close closes a Cayley database
func Close() {
	if store != nil {
		store.Close()
		store = nil
	}
}

// Healthcheck simply adds and then remove a quad in Cayley to ensure it is working
// It returns true when everything is ok
func Healthcheck() health.Status {
	var err error
	if store != nil {
		t := cayley.NewTransaction()
		q := cayley.Quad("cayley", "is", "healthy", "")
		t.AddQuad(q)
		t.RemoveQuad(q)
		glog.SetStderrThreshold("FATAL") // TODO REMOVE ME
		err = store.ApplyTransaction(t)
		glog.SetStderrThreshold("ERROR") // TODO REMOVE ME
	}

	return health.Status{IsEssential: true, IsHealthy: err == nil, Details: nil}
}

// toValue returns a single value from a path
// If the path does not lead to a value, an empty string is returned
// If the path leads to multiple values or if a database error occurs, an empty string and an error are returned
func toValue(p *path.Path) (string, error) {
	var value string

	it, _ := p.BuildIterator().Optimize()
	defer it.Close()
	for cayley.RawNext(it) {
		if value != "" {
			log.Error("failed query in toValue: used on an iterator containing multiple values")
			return "", ErrInconsistent
		}

		if it.Result() != nil {
			value = store.NameOf(it.Result())
		}
	}
	if it.Err() != nil {
		log.Errorf("failed query in toValue: %s", it.Err())
		return "", ErrBackendException
	}

	return value, nil
}

// toValues returns multiple values from a path
// If the path does not lead to any value, an empty array is returned
// If a database error occurs, an empty array and an error are returned
func toValues(p *path.Path) ([]string, error) {
	var values []string

	it, _ := p.BuildIterator().Optimize()
	defer it.Close()
	for cayley.RawNext(it) {
		if it.Result() != nil {
			value := store.NameOf(it.Result())
			if value != "" {
				values = append(values, value)
			}
		}
	}
	if it.Err() != nil {
		log.Errorf("failed query in toValues: %s", it.Err())
		return []string{}, ErrBackendException
	}

	return values, nil
}

// saveFields appends cayley's Save method to a path for each field in
// selectedFields, except the ones that appears also in exceptFields
func saveFields(p *path.Path, selectedFields []string, exceptFields []string) {
	for _, selectedField := range selectedFields {
		if utils.Contains(selectedField, exceptFields) {
			continue
		}
		p = p.Save(selectedField, selectedField)
	}
}
