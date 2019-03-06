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

// Layer is a layer with all the detected features and namespaces.
type Layer struct {
	// Hash is the sha-256 tarsum on the layer's blob content.
	Hash string `json:"hash"`
	// By contains a list of detectors scanned this Layer.
	By         []Detector       `json:"by"`
	Namespaces []LayerNamespace `json:"namespaces"`
	Features   []LayerFeature   `json:"features"`
}

func (l *Layer) GetFeatures() []Feature {
	features := make([]Feature, 0, len(l.Features))
	for _, f := range l.Features {
		features = append(features, f.Feature)
	}

	return features
}

func (l *Layer) GetNamespaces() []Namespace {
	namespaces := make([]Namespace, 0, len(l.Namespaces)+len(l.Features))
	for _, ns := range l.Namespaces {
		namespaces = append(namespaces, ns.Namespace)
	}
	for _, f := range l.Features {
		if f.PotentialNamespace.Valid() {
			namespaces = append(namespaces, f.PotentialNamespace)
		}
	}

	return namespaces
}

// LayerNamespace is a namespace with detection information.
type LayerNamespace struct {
	Namespace `json:"namespace"`

	// By is the detector found the namespace.
	By Detector `json:"by"`
}

// LayerFeature is a feature with detection information.
type LayerFeature struct {
	Feature `json:"feature"`

	// By is the detector found the feature.
	By                 Detector  `json:"by"`
	PotentialNamespace Namespace `json:"potentialNamespace"`
}
