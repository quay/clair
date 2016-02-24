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

import "github.com/coreos/clair/database"

var fetchers = make(map[string]Fetcher)

// Fetcher represents anything that can fetch vulnerabilities.
type Fetcher interface {
	// FetchUpdate gets vulnerability updates.
	FetchUpdate(database.Datastore) (FetcherResponse, error)

	// Clean deletes any allocated resources.
	// It is invoked when Clair stops.
	Clean()
}

// FetcherResponse represents the sum of results of an update.
type FetcherResponse struct {
	FlagName        string
	FlagValue       string
	Notes           []string
	Vulnerabilities []database.Vulnerability
}

// RegisterFetcher makes a Fetcher available by the provided name.
// If Register is called twice with the same name or if driver is nil,
// it panics.
func RegisterFetcher(name string, f Fetcher) {
	if name == "" {
		panic("updater: could not register a Fetcher with an empty name")
	}

	if f == nil {
		panic("updater: could not register a nil Fetcher")
	}

	if _, dup := fetchers[name]; dup {
		panic("updater: RegisterFetcher called twice for " + name)
	}

	fetchers[name] = f
}
