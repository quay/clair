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

// Ancestry is a manifest that keeps all layers in an image in order.
type Ancestry struct {
	// Name is a globally unique value for a set of layers. This is often the
	// sha256 digest of an OCI/Docker manifest.
	Name string `json:"name"`
	// By contains the processors that are used when computing the
	// content of this ancestry.
	By []Detector `json:"by"`
	// Layers should be ordered and i_th layer is the parent of i+1_th layer in
	// the slice.
	Layers []AncestryLayer `json:"layers"`
}

// Valid checks if the ancestry is compliant to spec.
func (a *Ancestry) Valid() bool {
	if a == nil {
		return false
	}

	if a.Name == "" {
		return false
	}

	for _, d := range a.By {
		if !d.Valid() {
			return false
		}
	}

	for _, l := range a.Layers {
		if !l.Valid() {
			return false
		}
	}

	return true
}

// AncestryLayer is a layer with all detected namespaced features.
type AncestryLayer struct {
	// Hash is the sha-256 tarsum on the layer's blob content.
	Hash string `json:"hash"`
	// Features are the features introduced by this layer when it was
	// processed.
	Features []AncestryFeature `json:"features"`
}

// Valid checks if the Ancestry Layer is compliant to the spec.
func (l *AncestryLayer) Valid() bool {
	if l == nil {
		return false
	}

	if l.Hash == "" {
		return false
	}

	return true
}

// GetFeatures returns the Ancestry's features.
func (l *AncestryLayer) GetFeatures() []NamespacedFeature {
	nsf := make([]NamespacedFeature, 0, len(l.Features))
	for _, f := range l.Features {
		nsf = append(nsf, f.NamespacedFeature)
	}

	return nsf
}

// AncestryFeature is a namespaced feature with the detectors used to
// find this feature.
type AncestryFeature struct {
	NamespacedFeature `json:"namespacedFeature"`

	// FeatureBy is the detector that detected the feature.
	FeatureBy Detector `json:"featureBy"`
	// NamespaceBy is the detector that detected the namespace.
	NamespaceBy Detector `json:"namespaceBy"`
}
