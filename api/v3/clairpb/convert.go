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

package clairpb

import (
	"encoding/json"
	"fmt"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/ext/versionfmt"
)

// PagedVulnerableAncestriesFromDatabaseModel converts database
// PagedVulnerableAncestries to api PagedVulnerableAncestries and assigns
// indexes to ancestries.
func PagedVulnerableAncestriesFromDatabaseModel(dbVuln *database.PagedVulnerableAncestries) (*PagedVulnerableAncestries, error) {
	if dbVuln == nil {
		return nil, nil
	}

	vuln, err := VulnerabilityFromDatabaseModel(dbVuln.Vulnerability)
	if err != nil {
		return nil, err
	}

	next := ""
	if !dbVuln.End {
		next = string(dbVuln.Next)
	}

	vulnAncestry := PagedVulnerableAncestries{
		Vulnerability: vuln,
		CurrentPage:   string(dbVuln.Current),
		NextPage:      next,
		Limit:         int32(dbVuln.Limit),
	}

	for index, ancestryName := range dbVuln.Affected {
		indexedAncestry := IndexedAncestryName{
			Name:  ancestryName,
			Index: int32(index),
		}
		vulnAncestry.Ancestries = append(vulnAncestry.Ancestries, &indexedAncestry)
	}

	return &vulnAncestry, nil
}

// NotificationFromDatabaseModel converts database notification, old and new
// vulnerabilities' paged vulnerable ancestries to be api notification.
func NotificationFromDatabaseModel(dbNotification database.VulnerabilityNotificationWithVulnerable) (*Notification, error) {
	var (
		noti Notification
		err  error
	)

	noti.Name = dbNotification.Name
	if !dbNotification.Created.IsZero() {
		noti.Created = fmt.Sprintf("%d", dbNotification.Created.Unix())
	}

	if !dbNotification.Notified.IsZero() {
		noti.Notified = fmt.Sprintf("%d", dbNotification.Notified.Unix())
	}

	if !dbNotification.Deleted.IsZero() {
		noti.Deleted = fmt.Sprintf("%d", dbNotification.Deleted.Unix())
	}

	noti.Old, err = PagedVulnerableAncestriesFromDatabaseModel(dbNotification.Old)
	if err != nil {
		return nil, err
	}

	noti.New, err = PagedVulnerableAncestriesFromDatabaseModel(dbNotification.New)
	if err != nil {
		return nil, err
	}

	return &noti, nil
}

func VulnerabilityFromDatabaseModel(dbVuln database.Vulnerability) (*Vulnerability, error) {
	metaString := ""
	if dbVuln.Metadata != nil {
		metadataByte, err := json.Marshal(dbVuln.Metadata)
		if err != nil {
			return nil, err
		}
		metaString = string(metadataByte)
	}

	return &Vulnerability{
		Name:          dbVuln.Name,
		NamespaceName: dbVuln.Namespace.Name,
		Description:   dbVuln.Description,
		Link:          dbVuln.Link,
		Severity:      string(dbVuln.Severity),
		Metadata:      metaString,
	}, nil
}

func VulnerabilityWithFixedInFromDatabaseModel(dbVuln database.VulnerabilityWithFixedIn) (*Vulnerability, error) {
	vuln, err := VulnerabilityFromDatabaseModel(dbVuln.Vulnerability)
	if err != nil {
		return nil, err
	}

	vuln.FixedBy = dbVuln.FixedInVersion
	return vuln, nil
}

// AncestryFromDatabaseModel converts database ancestry to api ancestry.
func AncestryFromDatabaseModel(dbAncestry database.Ancestry) *Ancestry {
	ancestry := &Ancestry{
		Name: dbAncestry.Name,
	}
	for _, layer := range dbAncestry.Layers {
		ancestry.Layers = append(ancestry.Layers, LayerFromDatabaseModel(layer))
	}
	return ancestry
}

// LayerFromDatabaseModel converts database layer to api layer.
func LayerFromDatabaseModel(dbLayer database.Layer) *Layer {
	layer := Layer{Hash: dbLayer.Hash}
	return &layer
}

// NamespacedFeatureFromDatabaseModel converts database namespacedFeature to api Feature.
func NamespacedFeatureFromDatabaseModel(feature database.NamespacedFeature) *Feature {
	version := feature.Feature.Version
	if version == versionfmt.MaxVersion {
		version = "None"
	}

	return &Feature{
		Name:          feature.Feature.Name,
		NamespaceName: feature.Namespace.Name,
		VersionFormat: feature.Namespace.VersionFormat,
		Version:       version,
	}
}
