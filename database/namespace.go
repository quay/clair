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

package database

// Namespace is the contextual information around features.
//
// e.g. Debian:7, NodeJS.
type Namespace struct {
	Name          string `json:"name"`
	VersionFormat string `json:"versionFormat"`
}

func NewNamespace(name string, versionFormat string) *Namespace {
	return &Namespace{name, versionFormat}
}

func (ns *Namespace) Valid() bool {
	if ns.Name == "" || ns.VersionFormat == "" {
		return false
	}
	return true
}
