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

package database

import (
	"database/sql/driver"
	"encoding/json"
	"time"
)

// Processors are extentions to scan layer's content.
type Processors struct {
	Listers   []string
	Detectors []string
}

// Ancestry is a manifest that keeps all layers in an image in order.
type Ancestry struct {
	Name string
	// Layers should be ordered and i_th layer is the parent of i+1_th layer in
	// the slice.
	Layers []Layer
}

// AncestryWithFeatures is an ancestry with namespaced features detected in the
// ancestry, which is processed by `ProcessedBy`.
type AncestryWithFeatures struct {
	Ancestry

	ProcessedBy Processors
	Features    []NamespacedFeature
}

// Layer corresponds to a layer in an image processed by `ProcessedBy`.
type Layer struct {
	// Hash is content hash of the layer.
	Hash string
}

// LayerWithContent is a layer with its detected namespaces and features by
// ProcessedBy.
type LayerWithContent struct {
	Layer

	ProcessedBy Processors
	Namespaces  []Namespace
	Features    []Feature
}

// Namespace is the contextual information around features.
//
// e.g. Debian:7, NodeJS.
type Namespace struct {
	Name          string
	VersionFormat string
}

// Feature represents a package detected in a layer but the namespace is not
// determined.
//
// e.g. Name: OpenSSL, Version: 1.0, VersionFormat: dpkg.
// dpkg is the version format of the installer package manager, which in this
// case could be dpkg or apk.
type Feature struct {
	Name          string
	Version       string
	VersionFormat string
}

// NamespacedFeature is a feature with determined namespace and can be affected
// by vulnerabilities.
//
// e.g. OpenSSL 1.0 dpkg Debian:7.
type NamespacedFeature struct {
	Feature

	Namespace Namespace
}

// AffectedNamespacedFeature is a namespaced feature affected by the
// vulnerabilities with fixed-in versions for this feature.
type AffectedNamespacedFeature struct {
	NamespacedFeature

	AffectedBy []VulnerabilityWithFixedIn
}

// VulnerabilityWithFixedIn is used for AffectedNamespacedFeature to retrieve
// the affecting vulnerabilities and the fixed-in versions for the feature.
type VulnerabilityWithFixedIn struct {
	Vulnerability

	FixedInVersion string
}

// AffectedFeature is used to determine whether a namespaced feature is affected
// by a Vulnerability. Namespace and Feature Name is unique. Affected Feature is
// bound to vulnerability.
type AffectedFeature struct {
	Namespace   Namespace
	FeatureName string
	// FixedInVersion is known next feature version that's not affected by the
	// vulnerability. Empty FixedInVersion means the unaffected version is
	// unknown.
	FixedInVersion string
	// AffectedVersion contains the version range to determine whether or not a
	// feature is affected.
	AffectedVersion string
}

// VulnerabilityID is an identifier for every vulnerability. Every vulnerability
// has unique namespace and name.
type VulnerabilityID struct {
	Name      string
	Namespace string
}

// Vulnerability represents CVE or similar vulnerability reports.
type Vulnerability struct {
	Name      string
	Namespace Namespace

	Description string
	Link        string
	Severity    Severity

	Metadata MetadataMap
}

// VulnerabilityWithAffected is an vulnerability with all known affected
// features.
type VulnerabilityWithAffected struct {
	Vulnerability

	Affected []AffectedFeature
}

// PagedVulnerableAncestries is a vulnerability with a page of affected
// ancestries each with a special index attached for streaming purpose. The
// current page number and next page number are for navigate.
type PagedVulnerableAncestries struct {
	Vulnerability

	// Affected is a map of special indexes to Ancestries, which the pair
	// should be unique in a stream. Every indexes in the map should be larger
	// than previous page.
	Affected map[int]string

	Limit   int
	Current PageNumber
	Next    PageNumber

	// End signals the end of the pages.
	End bool
}

// NotificationHook is a message sent to another service to inform of a change
// to a Vulnerability or the Ancestries affected by a Vulnerability. It contains
// the name of a notification that should be read and marked as read via the
// API.
type NotificationHook struct {
	Name string

	Created  time.Time
	Notified time.Time
	Deleted  time.Time
}

// VulnerabilityNotification is a notification for vulnerability changes.
type VulnerabilityNotification struct {
	NotificationHook

	Old *Vulnerability
	New *Vulnerability
}

// VulnerabilityNotificationWithVulnerable is a notification for vulnerability
// changes with vulnerable ancestries.
type VulnerabilityNotificationWithVulnerable struct {
	NotificationHook

	Old *PagedVulnerableAncestries
	New *PagedVulnerableAncestries
}

// PageNumber is used to do pagination.
type PageNumber string

type MetadataMap map[string]interface{}

// NullableAffectedNamespacedFeature is an affectednamespacedfeature with
// whether it's found in datastore.
type NullableAffectedNamespacedFeature struct {
	AffectedNamespacedFeature

	Valid bool
}

// NullableVulnerability is a vulnerability with whether the vulnerability is
// found in datastore.
type NullableVulnerability struct {
	VulnerabilityWithAffected

	Valid bool
}

func (mm *MetadataMap) Scan(value interface{}) error {
	if value == nil {
		return nil
	}

	// github.com/lib/pq decodes TEXT/VARCHAR fields into strings.
	val, ok := value.(string)
	if !ok {
		panic("got type other than []byte from database")
	}
	return json.Unmarshal([]byte(val), mm)
}

func (mm *MetadataMap) Value() (driver.Value, error) {
	json, err := json.Marshal(*mm)
	return string(json), err
}
