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

	"github.com/coreos/clair/api/token"
	"github.com/coreos/clair/database"
	"github.com/coreos/clair/ext/versionfmt"
)

func NotificationFromDatabaseModel(dbNotification database.VulnerabilityNotification, limit int, pageToken string, nextPage database.VulnerabilityNotificationPageNumber, key string) (*Notification, error) {
	var oldVuln *LayersIntroducingVulnerabilty
	if dbNotification.OldVulnerability != nil {
		v, err := LayersIntroducingVulnerabiltyFromDatabaseModel(*dbNotification.OldVulnerability)
		if err != nil {
			return nil, err
		}
		oldVuln = v
	}

	var newVuln *LayersIntroducingVulnerabilty
	if dbNotification.NewVulnerability != nil {
		v, err := LayersIntroducingVulnerabiltyFromDatabaseModel(*dbNotification.NewVulnerability)
		if err != nil {
			return nil, err
		}
		newVuln = v
	}

	var nextPageStr string
	if nextPage != database.NoVulnerabilityNotificationPage {
		nextPageBytes, _ := token.Marshal(nextPage, key)
		nextPageStr = string(nextPageBytes)
	}

	var created, notified, deleted string
	if !dbNotification.Created.IsZero() {
		created = fmt.Sprintf("%d", dbNotification.Created.Unix())
	}
	if !dbNotification.Notified.IsZero() {
		notified = fmt.Sprintf("%d", dbNotification.Notified.Unix())
	}
	if !dbNotification.Deleted.IsZero() {
		deleted = fmt.Sprintf("%d", dbNotification.Deleted.Unix())
	}

	return &Notification{
		Name:     dbNotification.Name,
		Created:  created,
		Notified: notified,
		Deleted:  deleted,
		Limit:    int32(limit),
		Page: &Page{
			ThisToken: pageToken,
			NextToken: nextPageStr,
			Old:       oldVuln,
			New:       newVuln,
		},
	}, nil
}

func LayersIntroducingVulnerabiltyFromDatabaseModel(dbVuln database.Vulnerability) (*LayersIntroducingVulnerabilty, error) {
	vuln, err := VulnerabilityFromDatabaseModel(dbVuln, true)
	if err != nil {
		return nil, err
	}
	var orderedLayers []*OrderedLayerName

	return &LayersIntroducingVulnerabilty{
		Vulnerability: vuln,
		Layers:        orderedLayers,
	}, nil
}

func VulnerabilityFromDatabaseModel(dbVuln database.Vulnerability, withFixedIn bool) (*Vulnerability, error) {
	metaString := ""
	if dbVuln.Metadata != nil {
		metadataByte, err := json.Marshal(dbVuln.Metadata)
		if err != nil {
			return nil, err
		}
		metaString = string(metadataByte)
	}

	vuln := Vulnerability{
		Name:          dbVuln.Name,
		NamespaceName: dbVuln.Namespace.Name,
		Description:   dbVuln.Description,
		Link:          dbVuln.Link,
		Severity:      string(dbVuln.Severity),
		Metadata:      metaString,
	}

	if dbVuln.FixedBy != versionfmt.MaxVersion {
		vuln.FixedBy = dbVuln.FixedBy
	}

	if withFixedIn {
		for _, dbFeatureVersion := range dbVuln.FixedIn {
			f, err := FeatureFromDatabaseModel(dbFeatureVersion, false)
			if err != nil {
				return nil, err
			}

			vuln.FixedInFeatures = append(vuln.FixedInFeatures, f)
		}
	}

	return &vuln, nil
}

func LayerFromDatabaseModel(dbLayer database.Layer) *Layer {
	layer := Layer{
		Name: dbLayer.Name,
	}
	for _, ns := range dbLayer.Namespaces {
		layer.NamespaceNames = append(layer.NamespaceNames, ns.Name)
	}

	return &layer
}

func FeatureFromDatabaseModel(fv database.FeatureVersion, withVulnerabilities bool) (*Feature, error) {
	version := fv.Version
	if version == versionfmt.MaxVersion {
		version = "None"
	}
	f := &Feature{
		Name:          fv.Feature.Name,
		NamespaceName: fv.Feature.Namespace.Name,
		VersionFormat: fv.Feature.Namespace.VersionFormat,
		Version:       version,
		AddedBy:       fv.AddedBy.Name,
	}

	if withVulnerabilities {
		for _, dbVuln := range fv.AffectedBy {
			// VulnerabilityFromDatabaseModel should be called without FixedIn,
			// Otherwise it might cause infinite loop
			vul, err := VulnerabilityFromDatabaseModel(dbVuln, false)
			if err != nil {
				return nil, err
			}

			f.Vulnerabilities = append(f.Vulnerabilities, vul)
		}
	}

	return f, nil
}
