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

type Error struct {
	Message string `json:"Layer`
}

type LayerEnvelope struct {
	Layer *Layer `json:"Layer,omitempty"`
	Error *Error `json:"Error,omitempty"`
}

type Layer struct {
	Name             string    `json:"Name,omitempty"`
	NamespaceName    string    `json:"NamespaceName,omitempty"`
	Path             string    `json:"Path,omitempty"`
	ParentName       string    `json:"ParentName,omitempty"`
	Format           string    `json:"Format,omitempty"`
	IndexedByVersion int       `json:"IndexedByVersion,omitempty"`
	Features         []Feature `json:"Features,omitempty"`
}

type Vulnerability struct {
	Name          string    `json:"Name,omitempty"`
	NamespaceName string    `json:"NamespaceName,omitempty"`
	Description   string    `json:"Description,omitempty"`
	Severity      string    `json:"Severity,omitempty"`
	FixedBy       string    `json:"FixedBy,omitempty"`
	FixedIn       []Feature `json:"FixedIn,omitempty"`
}

type Feature struct {
	Name            string          `json:"Name,omitempty"`
	Namespace       string          `json:"Namespace,omitempty"`
	Version         string          `json:"Version,omitempty"`
	Vulnerabilities []Vulnerability `json:"Vulnerabilities,omitempty"`
}

type Notification struct {
	Name     string                  `json:"Name,omitempty"`
	Created  string                  `json:"Created,omitempty"`
	Notified string                  `json:"Notified,omitempty"`
	Deleted  string                  `json:"Deleted,omitempty"`
	Limit    int                     `json:"Limit,omitempty"`
	Page     string                  `json:"Page,omitempty"`
	NextPage string                  `json:"NextPage,omitempty"`
	Old      VulnerabilityWithLayers `json:"Old,omitempty"`
	New      VulnerabilityWithLayers `json:"New,omitempty"`
	Changed  []string                `json:"Changed,omitempty"`
}

type VulnerabilityWithLayers struct {
	Vulnerability                  *Vulnerability `json:"Vulnerability,omitempty"`
	LayersIntroducingVulnerability []string       `json:"LayersIntroducingVulnerability,omitempty"`
}
