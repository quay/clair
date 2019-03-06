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

// Feature represents a package detected in a layer but the namespace is not
// determined.
//
// e.g. Name: Libssl1.0, Version: 1.0, VersionFormat: dpkg, Type: binary
// dpkg is the version format of the installer package manager, which in this
// case could be dpkg or apk.
type Feature struct {
	Name          string      `json:"name"`
	Version       string      `json:"version"`
	VersionFormat string      `json:"versionFormat"`
	Type          FeatureType `json:"type"`
}

// NamespacedFeature is a feature with determined namespace and can be affected
// by vulnerabilities.
//
// e.g. OpenSSL 1.0 dpkg Debian:7.
type NamespacedFeature struct {
	Feature `json:"feature"`

	Namespace Namespace `json:"namespace"`
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
	// FeatureType determines which type of package it affects.
	FeatureType FeatureType
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

// NullableAffectedNamespacedFeature is an affectednamespacedfeature with
// whether it's found in datastore.
type NullableAffectedNamespacedFeature struct {
	AffectedNamespacedFeature

	Valid bool
}

func NewFeature(name string, version string, versionFormat string, featureType FeatureType) *Feature {
	return &Feature{name, version, versionFormat, featureType}
}

func NewBinaryPackage(name string, version string, versionFormat string) *Feature {
	return &Feature{name, version, versionFormat, BinaryPackage}
}

func NewSourcePackage(name string, version string, versionFormat string) *Feature {
	return &Feature{name, version, versionFormat, SourcePackage}
}

func NewNamespacedFeature(namespace *Namespace, feature *Feature) *NamespacedFeature {
	// TODO: namespaced feature should use pointer values
	return &NamespacedFeature{*feature, *namespace}
}
