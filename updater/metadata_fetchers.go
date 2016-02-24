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

package updater

import (
	"sync"

	"github.com/coreos/clair/database"
)

var metadataFetchers = make(map[string]MetadataFetcher)

type VulnerabilityWithLock struct {
	*database.Vulnerability
	Lock sync.Mutex
}

// MetadataFetcher
type MetadataFetcher interface {
	// Load runs right before the Updater calls AddMetadata for each vulnerabilities.
	Load(database.Datastore) error

	// AddMetadata adds metadata to the given database.Vulnerability.
	// It is expected that the fetcher uses .Lock.Lock() when manipulating the Metadata map.
	AddMetadata(*VulnerabilityWithLock) error

	// Unload runs right after the Updater finished calling AddMetadata for every vulnerabilities.
	Unload()

	// Clean deletes any allocated resources.
	// It is invoked when Clair stops.
	Clean()
}

// RegisterFetcher makes a Fetcher available by the provided name.
// If Register is called twice with the same name or if driver is nil,
// it panics.
func RegisterMetadataFetcher(name string, f MetadataFetcher) {
	if name == "" {
		panic("updater: could not register a MetadataFetcher with an empty name")
	}

	if f == nil {
		panic("updater: could not register a nil MetadataFetcher")
	}

	if _, dup := fetchers[name]; dup {
		panic("updater: RegisterMetadataFetcher called twice for " + name)
	}

	metadataFetchers[name] = f
}
