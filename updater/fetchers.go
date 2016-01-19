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
	FetchUpdate(database.Datastore) (FetcherResponse, error)
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

// DoVulnerabilityNamespacing is an helper function for fetchers.
//
// It takes a Vulnerability that doesn't have a Namespace and split it into
// potentially multiple vulnerabilities that have a Namespace and only contains the FixedIn
// FeatureVersions corresponding to their Namespace.
//
// It helps simplifying the fetchers that share the same metadata about a Vulnerability regardless
// of their actual namespace (ie. same vulnerability information for every version of a distro).
func DoVulnerabilityNamespacing(v database.Vulnerability) []database.Vulnerability {
	vulnerabilitiesMap := make(map[string]*database.Vulnerability)

	featureVersions := v.FixedIn
	v.FixedIn = []database.FeatureVersion{}

	for _, fv := range featureVersions {
		if vulnerability, ok := vulnerabilitiesMap[fv.Feature.Namespace.Name]; !ok {
			newVulnerability := v
			newVulnerability.Namespace.Name = fv.Feature.Namespace.Name
			newVulnerability.FixedIn = []database.FeatureVersion{fv}

			vulnerabilitiesMap[fv.Feature.Namespace.Name] = &newVulnerability
		} else {
			vulnerability.FixedIn = append(vulnerability.FixedIn, fv)
		}
	}

	// Convert map into a slice.
	var vulnerabilities []database.Vulnerability
	for _, vulnerability := range vulnerabilitiesMap {
		vulnerabilities = append(vulnerabilities, *vulnerability)
	}

	return vulnerabilities
}
