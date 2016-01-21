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

package database

import "github.com/coreos/clair/utils/types"

// ID is only meant to be used by database implementations and should never be used for anything else.
type Model struct {
	ID int `json:"-"`
}

type Layer struct {
	Model

	Name          string
	EngineVersion int              `json:",omitempty"`
	Parent        *Layer           `json:",omitempty"`
	Namespace     *Namespace       `json:",omitempty"`
	Features      []FeatureVersion `json:",omitempty"`
}

type Namespace struct {
	Model

	Name string
}

type Feature struct {
	Model

	Name      string
	Namespace Namespace
	// FixedBy   map[types.Version]Vulnerability // <<-- WRONG.
}

type FeatureVersion struct {
	Model

	Feature    Feature
	Version    types.Version
	AffectedBy []Vulnerability `json:",omitempty"`
}

type Vulnerability struct {
	Model

	Name        string
	Namespace   Namespace
	Description string
	Link        string
	Severity    types.Priority

	FixedIn []FeatureVersion `json:",omitempty"`
	//Affects []FeatureVersion

	// For output purposes. Only make sense when the vulnerability
	// is already about a specific Feature/FeatureVersion.
	FixedBy types.Version `json:",omitempty"`
}

type NewVulnerabilityNotification struct {
	VulnerabilityID int
}

type NewVulnerabilityNotificationPage struct {
	Vulnerability Vulnerability
	Layers        []Layer
}

// ...
