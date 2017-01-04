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

// Package vulnmdsrc exposes functions to dynamically register vulnerability
// metadata sources used to update a Clair database.
package vulnmdsrc

import (
	"github.com/coreos/clair/database"
	"github.com/coreos/clair/utils/types"
)

// Appenders is the list of registered Appenders.
var Appenders = make(map[string]Appender)

// AppendFunc is the type of a callback provided to an Appender.
type AppendFunc func(metadataKey string, metadata interface{}, severity types.Priority)

// Appender represents anything that can fetch vulnerability metadata and
// append it to a Vulnerability.
type Appender interface {
	// BuildCache loads metadata into memory such that it can be quickly accessed
	// for future calls to Append.
	BuildCache(database.Datastore) error

	// AddMetadata adds metadata to the given database.Vulnerability.
	// It is expected that the fetcher uses .Lock.Lock() when manipulating the Metadata map.
	// Append
	Append(vulnName string, callback AppendFunc) error

	// PurgeCache deallocates metadata from memory after all calls to Append are
	// finished.
	PurgeCache()

	// Clean deletes any allocated resources.
	// It is invoked when Clair stops.
	Clean()
}

// RegisterAppender makes an Appender available by the provided name.
// If Register is called twice with the same name or if driver is nil,
// it panics.
func RegisterAppender(name string, a Appender) {
	if name == "" {
		panic("updater: could not register an Appender with an empty name")
	}

	if a == nil {
		panic("vulnmdsrc: could not register a nil Appender")
	}

	if _, dup := Appenders[name]; dup {
		panic("vulnmdsrc: RegisterAppender called twice for " + name)
	}

	Appenders[name] = a
}
