// Copyright 2018 clair authors
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
	"github.com/deckarep/golang-set"
)

// DeduplicateNamespaces deduplicates a list of namespaces.
func DeduplicateNamespaces(namespaces ...Namespace) []Namespace {
	nsSet := mapset.NewSet()
	for _, ns := range namespaces {
		nsSet.Add(ns)
	}

	uniqueNamespaces := make([]Namespace, 0, nsSet.Cardinality())
	for ns := range nsSet.Iter() {
		uniqueNamespaces = append(uniqueNamespaces, ns.(Namespace))
	}

	return uniqueNamespaces
}

// DeduplicateFeatures deduplicates a list of list of features.
func DeduplicateFeatures(features ...Feature) []Feature {
	fSet := mapset.NewSet()
	for _, f := range features {
		fSet.Add(f)
	}

	return ConvertFeatureSetToFeatures(fSet)
}

// ConvertFeatureSetToFeatures converts a feature set to an array of features
func ConvertFeatureSetToFeatures(features mapset.Set) []Feature {
	uniqueFeatures := make([]Feature, 0, features.Cardinality())
	for f := range features.Iter() {
		uniqueFeatures = append(uniqueFeatures, f.(Feature))
	}

	return uniqueFeatures
}

// FindKeyValueAndRollback wraps session FindKeyValue function with begin and
// roll back.
func FindKeyValueAndRollback(datastore Datastore, key string) (value string, ok bool, err error) {
	var tx Session
	tx, err = datastore.Begin()
	if err != nil {
		return
	}
	defer tx.Rollback()

	value, ok, err = tx.FindKeyValue(key)
	return
}

// PersistPartialLayerAndCommit wraps session PersistLayer function with begin and
// commit.
func PersistPartialLayerAndCommit(datastore Datastore, layer *Layer) error {
	tx, err := datastore.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if err := tx.PersistLayer(layer.Hash, layer.Features, layer.Namespaces, layer.By); err != nil {
		return err
	}

	return tx.Commit()
}

// PersistFeaturesAndCommit wraps session PersistFeaturesAndCommit function with begin and commit.
func PersistFeaturesAndCommit(datastore Datastore, features []Feature) error {
	tx, err := datastore.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if err := tx.PersistFeatures(features); err != nil {
		return err
	}
	return tx.Commit()
}

// PersistNamespacesAndCommit wraps session PersistNamespaces function with
// begin and commit.
func PersistNamespacesAndCommit(datastore Datastore, namespaces []Namespace) error {
	tx, err := datastore.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if err := tx.PersistNamespaces(namespaces); err != nil {
		return err
	}

	return tx.Commit()
}

// FindAncestryAndRollback wraps session FindAncestry function with begin and
// rollback.
func FindAncestryAndRollback(datastore Datastore, name string) (Ancestry, bool, error) {
	tx, err := datastore.Begin()
	defer tx.Rollback()

	if err != nil {
		return Ancestry{}, false, err
	}

	return tx.FindAncestry(name)
}

// FindLayerAndRollback wraps session FindLayer function with begin and rollback.
func FindLayerAndRollback(datastore Datastore, hash string) (layer Layer, ok bool, err error) {
	var tx Session
	if tx, err = datastore.Begin(); err != nil {
		return
	}

	defer tx.Rollback()
	layer, ok, err = tx.FindLayer(hash)
	return
}

// DeduplicateNamespacedFeatures returns a copy of all unique features in the
// input.
func DeduplicateNamespacedFeatures(features []NamespacedFeature) []NamespacedFeature {
	nsSet := mapset.NewSet()
	for _, ns := range features {
		nsSet.Add(ns)
	}

	uniqueFeatures := make([]NamespacedFeature, 0, nsSet.Cardinality())
	for ns := range nsSet.Iter() {
		uniqueFeatures = append(uniqueFeatures, ns.(NamespacedFeature))
	}

	return uniqueFeatures
}

// GetAncestryFeatures returns a list of unique namespaced features in the
// ancestry.
func GetAncestryFeatures(ancestry Ancestry) []NamespacedFeature {
	features := []NamespacedFeature{}
	for _, layer := range ancestry.Layers {
		features = append(features, layer.GetFeatures()...)
	}

	return DeduplicateNamespacedFeatures(features)
}

// UpsertAncestryAndCommit wraps session UpsertAncestry function with begin and commit.
func UpsertAncestryAndCommit(datastore Datastore, ancestry Ancestry) error {
	tx, err := datastore.Begin()
	if err != nil {
		return err
	}

	if err = tx.UpsertAncestry(ancestry); err != nil {
		tx.Rollback()
		return err
	}

	if err = tx.Commit(); err != nil {
		return err
	}

	return nil
}

// PersistNamespacedFeaturesAndCommit wraps session PersistNamespacedFeatures function
// with begin and commit.
func PersistNamespacedFeaturesAndCommit(datastore Datastore, features []NamespacedFeature) error {
	tx, err := datastore.Begin()
	if err != nil {
		return err
	}

	if err := tx.PersistNamespacedFeatures(features); err != nil {
		tx.Rollback()
		return err
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	return nil
}

// CacheRelatedVulnerabilityAndCommit wraps session CacheAffectedNamespacedFeatures
// function with begin and commit.
func CacheRelatedVulnerabilityAndCommit(datastore Datastore, features []NamespacedFeature) error {
	tx, err := datastore.Begin()
	if err != nil {
		return err
	}

	if err := tx.CacheAffectedNamespacedFeatures(features); err != nil {
		tx.Rollback()
		return err
	}

	return tx.Commit()
}

// IntersectDetectors returns the detectors in both d1 and d2.
func IntersectDetectors(d1 []Detector, d2 []Detector) []Detector {
	d1Set := mapset.NewSet()
	for _, d := range d1 {
		d1Set.Add(d)
	}

	d2Set := mapset.NewSet()
	for _, d := range d2 {
		d2Set.Add(d)
	}

	inter := d1Set.Intersect(d2Set)
	detectors := make([]Detector, 0, inter.Cardinality())
	for d := range inter.Iter() {
		detectors = append(detectors, d.(Detector))
	}

	return detectors
}

// DiffDetectors returns the detectors belongs to d1 but not d2
func DiffDetectors(d1 []Detector, d2 []Detector) []Detector {
	d1Set := mapset.NewSet()
	for _, d := range d1 {
		d1Set.Add(d)
	}

	d2Set := mapset.NewSet()
	for _, d := range d2 {
		d2Set.Add(d)
	}

	diff := d1Set.Difference(d2Set)
	detectors := make([]Detector, 0, diff.Cardinality())
	for d := range diff.Iter() {
		detectors = append(detectors, d.(Detector))
	}

	return detectors
}

// MergeLayers merges all content in new layer to l, where the content is
// updated.
func MergeLayers(l *Layer, new *Layer) *Layer {
	featureSet := mapset.NewSet()
	namespaceSet := mapset.NewSet()
	bySet := mapset.NewSet()

	for _, f := range l.Features {
		featureSet.Add(f)
	}

	for _, ns := range l.Namespaces {
		namespaceSet.Add(ns)
	}

	for _, d := range l.By {
		bySet.Add(d)
	}

	for _, feature := range new.Features {
		if !featureSet.Contains(feature) {
			l.Features = append(l.Features, feature)
			featureSet.Add(feature)
		}
	}

	for _, namespace := range new.Namespaces {
		if !namespaceSet.Contains(namespace) {
			l.Namespaces = append(l.Namespaces, namespace)
			namespaceSet.Add(namespace)
		}
	}

	for _, detector := range new.By {
		if !bySet.Contains(detector) {
			l.By = append(l.By, detector)
			bySet.Add(detector)
		}
	}

	return l
}
