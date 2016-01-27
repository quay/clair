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

package v1

type ErrorResponse struct {
	Error string
	Type  string
}

type Layer struct {
	Name             string
	Path             string
	Parent           string
	IndexedByVersion int
	Features         []Feature
}

type Vulnerability struct {
	Name        string
	Namespace   string
	Description string
	Severity    string
	FixedBy     string
	FixedIn     []Feature
}

type Feature struct {
	Name            string
	Namespace       string
	Version         string
	Vulnerabilities []Vulnerability
}

type Notification struct {
	Name     string
	Created  string
	Notified string
	Deleted  string
	Limit    int
	Page     string
	NextPage string
	Old      VulnerabilityWithLayers
	New      VulnerabilityWithLayers
	Changed  []string
}

type VulnerabilityWithLayers struct {
	Vulnerability                  Vulnerability
	LayersIntroducingVulnerability []string
}
