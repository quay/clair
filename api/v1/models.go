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

import (
	"errors"
	"fmt"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/utils/types"
)

type Error struct {
	Message string `json:"Layer`
}

type Layer struct {
	Name             string    `json:"Name,omitempty"`
	Namespace        string    `json:"Namespace,omitempty"`
	Path             string    `json:"Path,omitempty"`
	ParentName       string    `json:"ParentName,omitempty"`
	Format           string    `json:"Format,omitempty"`
	IndexedByVersion int       `json:"IndexedByVersion,omitempty"`
	Features         []Feature `json:"Features,omitempty"`
}

func LayerFromDatabaseModel(dbLayer database.Layer, withFeatures, withVulnerabilities bool) Layer {
	layer := Layer{
		Name:             dbLayer.Name,
		IndexedByVersion: dbLayer.EngineVersion,
	}

	if dbLayer.Parent != nil {
		layer.ParentName = dbLayer.Parent.Name
	}

	if dbLayer.Namespace != nil {
		layer.Namespace = dbLayer.Namespace.Name
	}

	if withFeatures || withVulnerabilities && dbLayer.Features != nil {
		for _, dbFeatureVersion := range dbLayer.Features {
			feature := Feature{
				Name:      dbFeatureVersion.Feature.Name,
				Namespace: dbFeatureVersion.Feature.Namespace.Name,
				Version:   dbFeatureVersion.Version.String(),
			}

			for _, dbVuln := range dbFeatureVersion.AffectedBy {
				vuln := Vulnerability{
					Name:        dbVuln.Name,
					Namespace:   dbVuln.Namespace.Name,
					Description: dbVuln.Description,
					Severity:    string(dbVuln.Severity),
					Metadata:    dbVuln.Metadata,
				}

				if dbVuln.FixedBy != types.MaxVersion {
					vuln.FixedBy = dbVuln.FixedBy.String()
				}
				feature.Vulnerabilities = append(feature.Vulnerabilities, vuln)
			}
			layer.Features = append(layer.Features, feature)
		}
	}

	return layer
}

type Vulnerability struct {
	Name        string                 `json:"Name,omitempty"`
	Namespace   string                 `json:"Namespace,omitempty"`
	Description string                 `json:"Description,omitempty"`
	Link        string                 `json:"Link,omitempty"`
	Severity    string                 `json:"Severity,omitempty"`
	Metadata    map[string]interface{} `json:"Metadata,omitempty"`
	FixedBy     string                 `json:"FixedBy,omitempty"`
	FixedIn     []Feature              `json:"FixedIn,omitempty"`
}

func (v Vulnerability) DatabaseModel() (database.Vulnerability, error) {
	severity := types.Priority(v.Severity)
	if !severity.IsValid() {
		return database.Vulnerability{}, errors.New("Invalid severity")
	}

	var dbFeatures []database.FeatureVersion
	for _, feature := range v.FixedIn {
		version, err := types.NewVersion(feature.Version)
		if err != nil {
			return database.Vulnerability{}, err
		}

		dbFeatures = append(dbFeatures, database.FeatureVersion{
			Feature: database.Feature{
				Name:      feature.Name,
				Namespace: database.Namespace{Name: feature.Namespace},
			},
			Version: version,
		})
	}

	return database.Vulnerability{
		Name:        v.Name,
		Namespace:   database.Namespace{Name: v.Namespace},
		Description: v.Description,
		Link:        v.Link,
		Severity:    severity,
		Metadata:    v.Metadata,
		FixedIn:     dbFeatures,
	}, nil
}

func VulnerabilityFromDatabaseModel(dbVuln database.Vulnerability, withFixedIn bool) Vulnerability {
	vuln := Vulnerability{
		Name:        dbVuln.Name,
		Namespace:   dbVuln.Namespace.Name,
		Description: dbVuln.Description,
		Link:        dbVuln.Link,
		Severity:    string(dbVuln.Severity),
		Metadata:    dbVuln.Metadata,
	}

	if withFixedIn {
		for _, dbFeatureVersion := range dbVuln.FixedIn {
			vuln.FixedIn = append(vuln.FixedIn, Feature{
				Name:      dbFeatureVersion.Feature.Name,
				Namespace: dbFeatureVersion.Feature.Namespace.Name,
				Version:   dbFeatureVersion.Version.String(),
			})
		}
	}

	return vuln
}

type Feature struct {
	Name            string          `json:"Name,omitempty"`
	Namespace       string          `json:"Namespace,omitempty"`
	Version         string          `json:"Version,omitempty"`
	Vulnerabilities []Vulnerability `json:"Vulnerabilities,omitempty"`
}

type Notification struct {
	Name     string                   `json:"Name,omitempty"`
	Created  string                   `json:"Created,omitempty"`
	Notified string                   `json:"Notified,omitempty"`
	Deleted  string                   `json:"Deleted,omitempty"`
	Limit    int                      `json:"Limit,omitempty"`
	Page     string                   `json:"Page,omitempty"`
	NextPage string                   `json:"NextPage,omitempty"`
	Old      *VulnerabilityWithLayers `json:"Old,omitempty"`
	New      VulnerabilityWithLayers  `json:"New,omitempty"`
	Changed  []string                 `json:"Changed,omitempty"`
}

func NotificationFromDatabaseModel(dbNotification database.VulnerabilityNotification, limit int, page, nextPage database.VulnerabilityNotificationPageNumber) Notification {
	var oldVuln *VulnerabilityWithLayers
	if dbNotification.OldVulnerability != nil {
		*oldVuln = VulnerabilityWithLayersFromDatabaseModel(*dbNotification.OldVulnerability)
	}

	var nextPageStr string
	if nextPage != database.NoVulnerabilityNotificationPage {
		nextPageStr = DBPageNumberToString(nextPage)
	}

	// TODO(jzelinskie): implement "changed" key
	return Notification{
		Name:     dbNotification.Name,
		Created:  fmt.Sprintf("%d", dbNotification.Created.Unix()),
		Notified: fmt.Sprintf("%d", dbNotification.Notified.Unix()),
		Deleted:  fmt.Sprintf("%d", dbNotification.Deleted.Unix()),
		Limit:    limit,
		Page:     DBPageNumberToString(page),
		NextPage: nextPageStr,
		Old:      oldVuln,
		New:      VulnerabilityWithLayersFromDatabaseModel(dbNotification.NewVulnerability),
	}
}

type VulnerabilityWithLayers struct {
	Vulnerability                  *Vulnerability `json:"Vulnerability,omitempty"`
	LayersIntroducingVulnerability []string       `json:"LayersIntroducingVulnerability,omitempty"`
}

func VulnerabilityWithLayersFromDatabaseModel(dbVuln database.Vulnerability) VulnerabilityWithLayers {
	vuln := VulnerabilityFromDatabaseModel(dbVuln, true)

	var layers []string
	for _, layer := range dbVuln.LayersIntroducingVulnerability {
		layers = append(layers, layer.Name)
	}

	return VulnerabilityWithLayers{
		Vulnerability:                  &vuln,
		LayersIntroducingVulnerability: layers,
	}
}

type LayerEnvelope struct {
	Layer *Layer `json:"Layer,omitempty"`
	Error *Error `json:"Error,omitempty"`
}

type NamespaceEnvelope struct {
	Namespaces *[]string `json:"Namespaces,omitempty"`
	Error      *Error    `json:"Error,omitempty"`
}

type VulnerabilityEnvelope struct {
	Vulnerability *Vulnerability `json:"Vulnerability,omitempty"`
	Error         *Error         `json:"Error,omitempty"`
}

type NotificationEnvelope struct {
	Notification *Notification `json:"Notification,omitempty"`
	Error        *Error        `json:"Error,omitempty"`
}

func pageStringToDBPageNumber(pageStr string) (database.VulnerabilityNotificationPageNumber, error) {
	// TODO(jzelinskie): turn pagination into an encrypted token
	var old, new int
	_, err := fmt.Sscanf(pageStr, "%d-%d", &old, &new)
	return database.VulnerabilityNotificationPageNumber{old, new}, err
}

func DBPageNumberToString(page database.VulnerabilityNotificationPageNumber) string {
	// TODO(jzelinskie): turn pagination into an encrypted token
	return fmt.Sprintf("%d-%d", page.OldVulnerability, page.NewVulnerability)
}
