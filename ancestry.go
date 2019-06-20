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

package clair

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/coreos/clair/database"
)

type layerIndexedFeature struct {
	Feature      *database.LayerFeature
	Namespace    *layerIndexedNamespace
	IntroducedIn int
}

type layerIndexedNamespace struct {
	Namespace    database.LayerNamespace `json:"namespace"`
	IntroducedIn int                     `json:"introducedIn"`
}

// AncestryBuilder builds an Ancestry, which contains an ordered list of layers
// and their features.
type AncestryBuilder struct {
	layerIndex int
	layerNames []string
	detectors  []database.Detector
	namespaces []layerIndexedNamespace // unique namespaces
	features   map[database.Detector][]layerIndexedFeature
}

// NewAncestryBuilder creates a new ancestry builder.
//
// ancestry builder takes in the extracted layer information and produce a set of
// namespaces, features, and the relation between features for the whole image.
func NewAncestryBuilder(detectors []database.Detector) *AncestryBuilder {
	return &AncestryBuilder{
		layerIndex: 0,
		detectors:  detectors,
		namespaces: make([]layerIndexedNamespace, 0),
		features:   make(map[database.Detector][]layerIndexedFeature),
	}
}

// AddLeafLayer adds a leaf layer to the ancestry builder, and computes the
// namespaced features.
func (b *AncestryBuilder) AddLeafLayer(layer *database.Layer) {
	b.layerNames = append(b.layerNames, layer.Hash)
	for i := range layer.Namespaces {
		b.updateNamespace(&layer.Namespaces[i])
	}

	allFeatureMap := map[database.Detector][]database.LayerFeature{}
	for i := range layer.Features {
		layerFeature := layer.Features[i]
		allFeatureMap[layerFeature.By] = append(allFeatureMap[layerFeature.By], layerFeature)
	}

	for _, detector := range b.detectors {
		b.addLayerFeatures(detector, allFeatureMap[detector])
	}

	b.layerIndex++
}

// Every detector inspects a set of files for the features
// therefore, if that set of files gives a different set of features, it
// should replace the existing features.
func (b *AncestryBuilder) addLayerFeatures(detector database.Detector, features []database.LayerFeature) {
	if len(features) == 0 {
		// TODO(sidac): we need to differentiate if the detector finds that all
		// features are removed ( a file change ), or the package installer is
		// removed ( a file deletion ), or there's no change in the file ( file
		// does not exist in the blob ) Right now, we're just assuming that no
		// change in the file because that's the most common case.
		return
	}

	existingFeatures := b.features[detector]
	currentFeatures := make([]layerIndexedFeature, 0, len(features))
	// Features that are not in the current layer should be removed.
	for i := range existingFeatures {
		feature := existingFeatures[i]
		for j := range features {
			if features[j] == *feature.Feature {
				currentFeatures = append(currentFeatures, feature)
				break
			}
		}
	}

	// Features that newly introduced in the current layer should be added.
	for i := range features {
		found := false
		for j := range existingFeatures {
			if *existingFeatures[j].Feature == features[i] {
				found = true
				break
			}
		}

		if !found {
			namespace, found := b.lookupNamespace(&features[i])
			if !found {
				continue
			}

			currentFeatures = append(currentFeatures, b.createLayerIndexedFeature(namespace, &features[i]))
		}
	}

	b.features[detector] = currentFeatures
}

// updateNamespace update the namespaces for the ancestry. It does the following things:
// 1. when a detector detects a new namespace, it's added to the ancestry.
// 2. when a detector detects a difference in the detected namespace, it
// replaces the namespace, and also move all features under that namespace to
// the new namespace.
func (b *AncestryBuilder) updateNamespace(layerNamespace *database.LayerNamespace) {
	var (
		previous     *layerIndexedNamespace
		foundUpgrade bool
	)

	newNSNames := strings.Split(layerNamespace.Name, ":")
	if len(newNSNames) != 2 {
		log.Error("invalid namespace name")
	}

	newNSName := newNSNames[0]
	newNSVersion := newNSNames[1]
	for i, ns := range b.namespaces {
		nsNames := strings.Split(ns.Namespace.Name, ":")
		if len(nsNames) != 2 {
			log.Error("invalid namespace name")
			continue
		}

		nsName := nsNames[0]
		nsVersion := nsNames[1]
		if ns.Namespace.VersionFormat == layerNamespace.VersionFormat && nsName == newNSName {
			if nsVersion != newNSVersion {
				previous = &b.namespaces[i]
				foundUpgrade = true
				break
			} else {
				// not changed
				return
			}
		}
	}

	// we didn't found the namespace is a upgrade from another namespace, so we
	// simply add it.
	if !foundUpgrade {
		b.namespaces = append(b.namespaces, layerIndexedNamespace{
			Namespace:    *layerNamespace,
			IntroducedIn: b.layerIndex,
		})

		return
	}

	// All features referencing to this namespace are now pointing to the new namespace.
	// Also those features are now treated as introduced in the same layer as
	// when this new namespace is introduced.
	previous.Namespace = *layerNamespace
	previous.IntroducedIn = b.layerIndex

	for _, features := range b.features {
		for i, feature := range features {
			if feature.Namespace == previous {
				features[i].IntroducedIn = previous.IntroducedIn
			}
		}
	}
}

func (b *AncestryBuilder) createLayerIndexedFeature(namespace *layerIndexedNamespace, feature *database.LayerFeature) layerIndexedFeature {
	return layerIndexedFeature{
		Feature:      feature,
		Namespace:    namespace,
		IntroducedIn: b.layerIndex,
	}
}

func (b *AncestryBuilder) lookupNamespace(feature *database.LayerFeature) (*layerIndexedNamespace, bool) {
	matchedNamespaces := []*layerIndexedNamespace{}
	if feature.PotentialNamespace.Name != "" {
		a := &layerIndexedNamespace{
			Namespace: database.LayerNamespace{
				Namespace: feature.PotentialNamespace,
			},
			IntroducedIn: b.layerIndex,
		}
		matchedNamespaces = append(matchedNamespaces, a)
	} else {

		for i, namespace := range b.namespaces {
			if namespace.Namespace.VersionFormat == feature.VersionFormat {
				matchedNamespaces = append(matchedNamespaces, &b.namespaces[i])
			}
		}
	}

	if len(matchedNamespaces) == 1 {
		return matchedNamespaces[0], true
	}

	serialized, _ := json.Marshal(matchedNamespaces)
	fields := log.Fields{
		"feature.Name":               feature.Name,
		"feature.VersionFormat":      feature.VersionFormat,
		"ancestryBuilder.namespaces": string(serialized),
	}

	if len(matchedNamespaces) > 1 {
		log.WithFields(fields).Warn("skip features with ambiguous namespaces")
	} else {
		log.WithFields(fields).Warn("skip features with no matching namespace")
	}

	return nil, false
}

func (b *AncestryBuilder) ancestryFeatures(index int) []database.AncestryFeature {
	ancestryFeatures := []database.AncestryFeature{}
	for detector, features := range b.features {
		for _, feature := range features {
			if feature.IntroducedIn == index {
				ancestryFeatures = append(ancestryFeatures, database.AncestryFeature{
					NamespacedFeature: database.NamespacedFeature{
						Feature:   feature.Feature.Feature,
						Namespace: feature.Namespace.Namespace.Namespace,
					},
					FeatureBy:   detector,
					NamespaceBy: feature.Namespace.Namespace.By,
				})
			}
		}
	}

	return ancestryFeatures
}

func (b *AncestryBuilder) ancestryLayers() []database.AncestryLayer {
	layers := make([]database.AncestryLayer, 0, b.layerIndex)
	for i := 0; i < b.layerIndex; i++ {
		layers = append(layers, database.AncestryLayer{
			Hash:     b.layerNames[i],
			Features: b.ancestryFeatures(i),
		})
	}

	return layers
}

// Ancestry produces an Ancestry from the builder.
func (b *AncestryBuilder) Ancestry(name string) *database.Ancestry {
	if name == "" {
		// TODO(sidac): we'll use the computed ancestry name in the future.
		// During the transition, it still requires the user to use the correct
		// ancestry name.
		name = ancestryName(b.layerNames)
		log.WithField("ancestry.Name", name).Warn("generated ancestry name since it's not specified")
	}

	return &database.Ancestry{
		Name:   name,
		By:     b.detectors,
		Layers: b.ancestryLayers(),
	}
}

// SaveAncestry saves an ancestry to the datastore.
func SaveAncestry(store database.Datastore, ancestry *database.Ancestry) error {
	log.WithField("ancestry.Name", ancestry.Name).Debug("saving ancestry")
	features := []database.NamespacedFeature{}
	for _, layer := range ancestry.Layers {
		features = append(features, layer.GetFeatures()...)
	}

	if err := database.PersistNamespacedFeaturesAndCommit(store, features); err != nil {
		return StorageError
	}

	if err := database.UpsertAncestryAndCommit(store, ancestry); err != nil {
		return StorageError
	}

	if err := database.CacheRelatedVulnerabilityAndCommit(store, features); err != nil {
		return StorageError
	}

	return nil
}

// IsAncestryCached checks if the ancestry is already cached in the database with the current set of detectors.
func IsAncestryCached(store database.Datastore, name string, layerHashes []string) (bool, error) {
	if name == "" {
		// TODO(sidac): we'll use the computed ancestry name in the future.
		// During the transition, it still requires the user to use the correct
		// ancestry name.
		name = ancestryName(layerHashes)
		log.WithField("ancestry.Name", name).Warn("generated ancestry name since it's not specified")
	}

	ancestry, found, err := database.FindAncestryAndRollback(store, name)
	if err != nil {
		log.WithError(err).WithField("ancestry.Name", name).Error("failed to query ancestry in database")
		return false, StorageError
	}

	if found {
		if len(database.DiffDetectors(EnabledDetectors(), ancestry.By)) == 0 {
			log.WithField("ancestry.Name", name).Debug("found cached ancestry")
		} else {
			log.WithField("ancestry.Name", name).Debug("found outdated ancestry cache")
		}
	} else {
		log.WithField("ancestry.Name", name).Debug("ancestry not cached")
	}

	return found && len(database.DiffDetectors(EnabledDetectors(), ancestry.By)) == 0, nil
}

func ancestryName(layerHashes []string) string {
	tag := sha256.Sum256([]byte(strings.Join(layerHashes, ",")))
	return hex.EncodeToString(tag[:])
}
