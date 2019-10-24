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

// Package redhatcpe implements image post-processor which shares
// namespace (CPEs) between layers
package redhatcpe

import (
	"github.com/quay/clair/v3/database"
	"github.com/quay/clair/v3/ext/featurefmt/redhatrpm"
	"github.com/quay/clair/v3/ext/imgpostprocessor"
	"github.com/quay/clair/v3/ext/versionfmt/rpm"
)

type postProcessor struct{}

func init() {
	imgpostprocessor.RegisterPostProcessor("redhat-cpe-postprocessor", &postProcessor{})
}

// PostProcessImage shares CPE namespaces between Red Hat's content.
// Red Hat images contains namespaces in form of CPE strings. But there are few expections where CPEs are missing.
// 1. Base layer (layer[0]) is missing namespace definition.
//		- namespaces need to be shared from layer[1]
// 2. Customers layers build on top of RH image are also missing CPEs namespaces
//		- namespaces need to be shared from last Red Hat's layers which defines CPEs
// THis plugin doesn't touch any content which was not extracted by redhat-rpm detector
func (postProcessor *postProcessor) PostProcessImage(layers []*database.LayerScanResult) ([]*database.LayerScanResult, error) {
	if !isRedHatImage(layers) {
		return layers, nil
	}
	// extract CPEs from layers where CPEs are defined
	layerNamespaces := extractCPEs(layers)

	// now filter-out packages which just holds CPE information
	layers = filterOutNamespaceHolderPkg(layers)

	// copy namespaces to layers where CPEs are missing
	sharedLayerNamespaces := shareNamespaces(layers, layerNamespaces)
	var postProcessedLayers []*database.LayerScanResult
	for _, layer := range layers {
		_, ok := layerNamespaces[layer.NewScanResultLayer.Hash]
		if !ok {
			layer = applyNewNamespaces(layer, sharedLayerNamespaces[layer.NewScanResultLayer.Hash])
		}
		postProcessedLayers = append(postProcessedLayers, layer)
	}
	return postProcessedLayers, nil
}

// isRedHatImage detect if image has Red Hat's content
func isRedHatImage(layers []*database.LayerScanResult) bool {
	// Red Hat base image has always at least 2 layers
	if len(layers) < 2 {
		return false
	}
	cpeNamespaces := extractCPEs(layers)
	if len(cpeNamespaces) != 0 {
		// There are no layers with CPE namespaces
		return true
	}
	return false
}

// extractCPEs gets CPE namespaces from package holders
func extractCPEs(layers []*database.LayerScanResult) map[string][]string {
	layerCpes := map[string][]string{}
	for _, layer := range layers {
		for _, pkg := range layer.NewScanResultLayer.Features {
			if pkg.By.Name == redhatrpm.Name && pkg.Feature == redhatrpm.NamespaceHolderPackage {
				namespace := pkg.PotentialNamespace.Name
				layerCpes[layer.NewScanResultLayer.Hash] = appendUnique(layerCpes[layer.NewScanResultLayer.Hash], namespace)
			}
		}
		for _, pkg := range layer.ExistingLayer.Features {
			if pkg.By.Name == redhatrpm.Name {
				if pkg.PotentialNamespace.Name != "" {
					namespace := pkg.PotentialNamespace.Name
					layerCpes[layer.ExistingLayer.Hash] = appendUnique(layerCpes[layer.ExistingLayer.Hash], namespace)
				}
			}
		}
	}

	return layerCpes
}

// filterOutNamespaceHolderPkg removes packages which were just used as namaspace holders
func filterOutNamespaceHolderPkg(layers []*database.LayerScanResult) []*database.LayerScanResult {
	for _, layer := range layers {
		var filteredPackages []database.LayerFeature
		for _, pkg := range layer.NewScanResultLayer.Features {
			if pkg.Feature != redhatrpm.NamespaceHolderPackage {
				filteredPackages = append(filteredPackages, pkg)
			}
		}
		layer.NewScanResultLayer.Features = filteredPackages

	}
	return layers
}

// filterOutRedHatPackages keeps non-Red Hat's packages in layer and extract RH content
func filterOutRedHatPackages(layer *database.LayerScanResult) (*database.LayerScanResult, []database.LayerFeature) {
	var filteredPackages []database.LayerFeature
	var redHatPackages []database.LayerFeature
	for _, pkg := range layer.NewScanResultLayer.Features {
		if pkg.By.Name == redhatrpm.Name {
			redHatPackages = append(redHatPackages, pkg)
		} else {
			filteredPackages = append(filteredPackages, pkg)
		}
	}
	layer.NewScanResultLayer.Features = filteredPackages

	return layer, redHatPackages
}

// applyNewNamespaces use CPE namespaces in Red Hat's features and add them to given layer
func applyNewNamespaces(layer *database.LayerScanResult, cpes []string) *database.LayerScanResult {
	layer, redHatFeatures := filterOutRedHatPackages(layer)
	var redHatFeaturesWithCpe []database.LayerFeature
	for _, feature := range redHatFeatures {
		for _, cpe := range cpes {
			feature.PotentialNamespace = database.Namespace{
				Name:          cpe,
				VersionFormat: rpm.ParserName,
			}
			redHatFeaturesWithCpe = append(redHatFeaturesWithCpe, feature)
		}
	}
	layer.NewScanResultLayer.Features = append(layer.NewScanResultLayer.Features, redHatFeaturesWithCpe...)

	return layer
}

// shareNamespaces shares CPE namespaces with layers where namespaces are missing
func shareNamespaces(layers []*database.LayerScanResult, layerNamespaces map[string][]string) map[string][]string {
	// from bottom to top
	newNamespaces := map[string][]string{}
	for key, value := range layerNamespaces {
		newNamespaces[key] = value
	}
	var previousLayerNamespace []string
	for i := 0; i < len(layers); i++ {
		cpes, ok := newNamespaces[layers[i].NewScanResultLayer.Hash]
		if !ok || len(cpes) == 0 {
			newNamespaces[layers[i].NewScanResultLayer.Hash] = previousLayerNamespace
		}
		previousLayerNamespace = newNamespaces[layers[i].NewScanResultLayer.Hash]
	}
	// from top to bottom
	previousLayerNamespace = []string{}
	for i := len(layers) - 1; i >= 0; i-- {
		cpes, ok := newNamespaces[layers[i].NewScanResultLayer.Hash]
		if !ok || len(cpes) == 0 {
			newNamespaces[layers[i].NewScanResultLayer.Hash] = previousLayerNamespace
		}
		previousLayerNamespace = newNamespaces[layers[i].NewScanResultLayer.Hash]
	}
	return newNamespaces
}

func appendUnique(items []string, item string) []string {
	for _, value := range items {
		if value == item {
			return items
		}
	}
	items = append(items, item)
	return items
}
