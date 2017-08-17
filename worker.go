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

package clair

import (
	"errors"
	"regexp"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/ext/featurefmt"
	"github.com/coreos/clair/ext/featurens"
	"github.com/coreos/clair/ext/imagefmt"
	"github.com/coreos/clair/pkg/commonerr"
	"github.com/coreos/clair/pkg/strutil"
)

const (
	logLayerName = "layer"
)

var (
	// ErrUnsupported is the error that should be raised when an OS or package
	// manager is not supported.
	ErrUnsupported = commonerr.NewBadRequestError("worker: OS and/or package manager are not supported")

	// ErrParentUnknown is the error that should be raised when a parent layer
	// has yet to be processed for the current layer.
	ErrParentUnknown = commonerr.NewBadRequestError("worker: parent layer is unknown, it must be processed first")

	urlParametersRegexp = regexp.MustCompile(`(\?|\&)([^=]+)\=([^ &]+)`)

	// Processors contain the names of namespace detectors and feature listers
	// enabled in this instance of Clair.
	//
	// Processors are initialized during booting and configured in the
	// configuration file.
	Processors database.Processors
)

type WorkerConfig struct {
	EnabledDetectors []string `yaml:"namespace_detectors"`
	EnabledListers   []string `yaml:"feature_listers"`
}

// LayerRequest represents all information necessary to download and process a
// layer.
type LayerRequest struct {
	Hash    string
	Path    string
	Headers map[string]string
}

// partialLayer stores layer's content detected by `processedBy` processors.
type partialLayer struct {
	hash        string
	processedBy database.Processors
	namespaces  []database.Namespace
	features    []database.Feature

	err error
}

// processRequest stores parameters used for processing layers.
type processRequest struct {
	request LayerRequest
	// notProcessedBy represents a set of processors used to process the
	// request.
	notProcessedBy database.Processors
}

// cleanURL removes all parameters from an URL.
func cleanURL(str string) string {
	return urlParametersRegexp.ReplaceAllString(str, "")
}

// processLayers in parallel processes a set of requests for unique set of layers
// and returns sets of unique namespaces, features and layers to be inserted
// into the database.
func processRequests(imageFormat string, toDetect []processRequest) ([]database.Namespace, []database.Feature, map[string]partialLayer, error) {
	wg := &sync.WaitGroup{}
	wg.Add(len(toDetect))
	results := make([]partialLayer, len(toDetect))
	for i := range toDetect {
		go func(req *processRequest, res *partialLayer) {
			res.hash = req.request.Hash
			res.processedBy = req.notProcessedBy
			res.namespaces, res.features, res.err = detectContent(imageFormat, req.request.Hash, req.request.Path, req.request.Headers, req.notProcessedBy)
			wg.Done()
		}(&toDetect[i], &results[i])
	}
	wg.Wait()
	distinctNS := map[database.Namespace]struct{}{}
	distinctF := map[database.Feature]struct{}{}

	errs := []error{}
	for _, r := range results {
		errs = append(errs, r.err)
	}

	if err := commonerr.CombineErrors(errs...); err != nil {
		return nil, nil, nil, err
	}

	updates := map[string]partialLayer{}
	for _, r := range results {
		for _, ns := range r.namespaces {
			distinctNS[ns] = struct{}{}
		}

		for _, f := range r.features {
			distinctF[f] = struct{}{}
		}

		if _, ok := updates[r.hash]; !ok {
			updates[r.hash] = r
		} else {
			return nil, nil, nil, errors.New("Duplicated updates is not allowed")
		}
	}

	namespaces := make([]database.Namespace, 0, len(distinctNS))
	features := make([]database.Feature, 0, len(distinctF))

	for ns := range distinctNS {
		namespaces = append(namespaces, ns)
	}

	for f := range distinctF {
		features = append(features, f)
	}
	return namespaces, features, updates, nil
}

func getLayer(datastore database.Datastore, req LayerRequest) (layer database.LayerWithContent, preq *processRequest, err error) {
	var ok bool
	tx, err := datastore.Begin()
	if err != nil {
		return
	}
	defer tx.Rollback()

	layer, ok, err = tx.FindLayerWithContent(req.Hash)
	if err != nil {
		return
	}

	if !ok {
		l := database.Layer{Hash: req.Hash}
		err = tx.PersistLayer(l)
		if err != nil {
			return
		}

		if err = tx.Commit(); err != nil {
			return
		}

		layer = database.LayerWithContent{Layer: l}
		preq = &processRequest{
			request:        req,
			notProcessedBy: Processors,
		}
	} else {
		notProcessed := getNotProcessedBy(layer.ProcessedBy)
		if !(len(notProcessed.Detectors) == 0 && len(notProcessed.Listers) == 0 && ok) {
			preq = &processRequest{
				request:        req,
				notProcessedBy: notProcessed,
			}
		}
	}
	return
}

// processLayers processes a set of post layer requests, stores layers and
// returns an ordered list of processed layers with detected features and
// namespaces.
func processLayers(datastore database.Datastore, imageFormat string, requests []LayerRequest) ([]database.LayerWithContent, error) {
	toDetect := []processRequest{}
	layers := map[string]database.LayerWithContent{}
	for _, req := range requests {
		if _, ok := layers[req.Hash]; ok {
			continue
		}
		layer, preq, err := getLayer(datastore, req)
		if err != nil {
			return nil, err
		}
		layers[req.Hash] = layer
		if preq != nil {
			toDetect = append(toDetect, *preq)
		}
	}

	namespaces, features, partialRes, err := processRequests(imageFormat, toDetect)
	if err != nil {
		return nil, err
	}

	// Store partial results.
	if err := persistNamespaces(datastore, namespaces); err != nil {
		return nil, err
	}

	if err := persistFeatures(datastore, features); err != nil {
		return nil, err
	}

	for _, res := range partialRes {
		if err := persistPartialLayer(datastore, res); err != nil {
			return nil, err
		}
	}

	// NOTE(Sida): The full layers are computed using partially
	// processed layers in current database session. If any other instances of
	// Clair are changing some layers in this set of layers, it might generate
	// different results especially when the other Clair is with different
	// processors.
	completeLayers := []database.LayerWithContent{}
	for _, req := range requests {
		if partialLayer, ok := partialRes[req.Hash]; ok {
			completeLayers = append(completeLayers, combineLayers(layers[req.Hash], partialLayer))
		} else {
			completeLayers = append(completeLayers, layers[req.Hash])
		}
	}

	return completeLayers, nil
}

func persistPartialLayer(datastore database.Datastore, layer partialLayer) error {
	tx, err := datastore.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if err := tx.PersistLayerContent(layer.hash, layer.namespaces, layer.features, layer.processedBy); err != nil {
		return err
	}
	return tx.Commit()
}

func persistFeatures(datastore database.Datastore, features []database.Feature) error {
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

func persistNamespaces(datastore database.Datastore, namespaces []database.Namespace) error {
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

// combineLayers merges `layer` and `partial` without duplicated content.
func combineLayers(layer database.LayerWithContent, partial partialLayer) database.LayerWithContent {
	mapF := map[database.Feature]struct{}{}
	mapNS := map[database.Namespace]struct{}{}
	for _, f := range layer.Features {
		mapF[f] = struct{}{}
	}
	for _, ns := range layer.Namespaces {
		mapNS[ns] = struct{}{}
	}
	for _, f := range partial.features {
		mapF[f] = struct{}{}
	}
	for _, ns := range partial.namespaces {
		mapNS[ns] = struct{}{}
	}
	features := make([]database.Feature, 0, len(mapF))
	namespaces := make([]database.Namespace, 0, len(mapNS))
	for f := range mapF {
		features = append(features, f)
	}
	for ns := range mapNS {
		namespaces = append(namespaces, ns)
	}

	layer.ProcessedBy.Detectors = append(layer.ProcessedBy.Detectors, strutil.CompareStringLists(partial.processedBy.Detectors, layer.ProcessedBy.Detectors)...)
	layer.ProcessedBy.Listers = append(layer.ProcessedBy.Listers, strutil.CompareStringLists(partial.processedBy.Listers, layer.ProcessedBy.Listers)...)
	return database.LayerWithContent{
		Layer: database.Layer{
			Hash: layer.Hash,
		},
		ProcessedBy: layer.ProcessedBy,
		Features:    features,
		Namespaces:  namespaces,
	}
}

func isAncestryProcessed(datastore database.Datastore, name string) (bool, error) {
	tx, err := datastore.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	_, processed, ok, err := tx.FindAncestry(name)
	if err != nil {
		return false, err
	}
	if !ok {
		return false, nil
	}

	notProcessed := getNotProcessedBy(processed)
	return len(notProcessed.Detectors) == 0 && len(notProcessed.Listers) == 0, nil
}

// ProcessAncestry downloads and scans an ancestry if it's not scanned by all
// enabled processors in this instance of Clair.
func ProcessAncestry(datastore database.Datastore, imageFormat, name string, layerRequest []LayerRequest) error {
	var err error
	if name == "" {
		return commonerr.NewBadRequestError("could not process a layer which does not have a name")
	}

	if imageFormat == "" {
		return commonerr.NewBadRequestError("could not process a layer which does not have a format")
	}

	if ok, err := isAncestryProcessed(datastore, name); ok && err == nil {
		log.WithField("ancestry", name).Debug("Ancestry is processed")
		return nil
	} else if err != nil {
		return err
	}

	layers, err := processLayers(datastore, imageFormat, layerRequest)
	if err != nil {
		return err
	}

	if !validateProcessors(layers) {
		// This error might be triggered because of multiple workers are
		// processing the same instance with different processors.
		return errors.New("ancestry layers are scanned with different listers and detectors")
	}

	return processAncestry(datastore, name, layers)
}

func processAncestry(datastore database.Datastore, name string, layers []database.LayerWithContent) error {
	ancestryFeatures, err := computeAncestryFeatures(layers)
	if err != nil {
		return err
	}

	ancestryLayers := make([]database.Layer, 0, len(layers))
	for _, layer := range layers {
		ancestryLayers = append(ancestryLayers, layer.Layer)
	}

	log.WithFields(log.Fields{
		"ancestry":           name,
		"number of features": len(ancestryFeatures),
		"processed by":       Processors,
		"number of layers":   len(ancestryLayers),
	}).Debug("compute ancestry features")

	if err := persistNamespacedFeatures(datastore, ancestryFeatures); err != nil {
		return err
	}

	tx, err := datastore.Begin()
	if err != nil {
		return err
	}

	err = tx.UpsertAncestry(database.Ancestry{Name: name, Layers: ancestryLayers}, ancestryFeatures, Processors)
	if err != nil {
		tx.Rollback()
		return err
	}

	err = tx.Commit()
	if err != nil {
		return err
	}
	return nil
}

func persistNamespacedFeatures(datastore database.Datastore, features []database.NamespacedFeature) error {
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

	tx, err = datastore.Begin()
	if err != nil {
		return err
	}

	if err := tx.CacheAffectedNamespacedFeatures(features); err != nil {
		tx.Rollback()
		return err
	}

	return tx.Commit()
}

// validateProcessors checks if the layers processed by same set of processors.
func validateProcessors(layers []database.LayerWithContent) bool {
	if len(layers) == 0 {
		return true
	}
	detectors := layers[0].ProcessedBy.Detectors
	listers := layers[0].ProcessedBy.Listers

	for _, l := range layers[1:] {
		if len(strutil.CompareStringLists(detectors, l.ProcessedBy.Detectors)) != 0 ||
			len(strutil.CompareStringLists(listers, l.ProcessedBy.Listers)) != 0 {
			return false
		}
	}
	return true
}

// computeAncestryFeatures computes the features in an ancestry based on all
// layers.
func computeAncestryFeatures(ancestryLayers []database.LayerWithContent) ([]database.NamespacedFeature, error) {
	// version format -> namespace
	namespaces := map[string]database.Namespace{}
	// version format -> feature ID -> feature
	features := map[string]map[string]database.NamespacedFeature{}
	for _, layer := range ancestryLayers {
		// At start of the loop, namespaces and features always contain the
		// previous layer's result.
		for _, ns := range layer.Namespaces {
			namespaces[ns.VersionFormat] = ns
		}

		// version format -> feature ID -> feature
		currentFeatures := map[string]map[string]database.NamespacedFeature{}
		for _, f := range layer.Features {
			if ns, ok := namespaces[f.VersionFormat]; ok {
				var currentMap map[string]database.NamespacedFeature
				if currentMap, ok = currentFeatures[f.VersionFormat]; !ok {
					currentFeatures[f.VersionFormat] = make(map[string]database.NamespacedFeature)
					currentMap = currentFeatures[f.VersionFormat]
				}

				inherited := false
				if mapF, ok := features[f.VersionFormat]; ok {
					if parentFeature, ok := mapF[f.Name+":"+f.Version]; ok {
						currentMap[f.Name+":"+f.Version] = parentFeature
						inherited = true
					}
				}

				if !inherited {
					currentMap[f.Name+":"+f.Version] = database.NamespacedFeature{
						Feature:   f,
						Namespace: ns,
					}
				}

			} else {
				return nil, errors.New("No corresponding version format")
			}
		}

		// NOTE(Sida): we update the feature map in some version format
		// only if there's at least one feature with that version format. This
		// approach won't differentiate feature file removed vs all detectable
		// features removed from that file vs feature file not changed.
		//
		// One way to differentiate (feature file removed or not changed) vs
		// all detectable features removed is to pass in the file status.
		for vf, mapF := range currentFeatures {
			features[vf] = mapF
		}
	}

	ancestryFeatures := []database.NamespacedFeature{}
	for _, featureMap := range features {
		for _, feature := range featureMap {
			ancestryFeatures = append(ancestryFeatures, feature)
		}
	}
	return ancestryFeatures, nil
}

// getNotProcessedBy returns a processors, which contains the detectors and
// listers not in `processedBy` but implemented in the current clair instance.
func getNotProcessedBy(processedBy database.Processors) database.Processors {
	notProcessedLister := strutil.CompareStringLists(Processors.Listers, processedBy.Listers)
	notProcessedDetector := strutil.CompareStringLists(Processors.Detectors, processedBy.Detectors)
	return database.Processors{
		Listers:   notProcessedLister,
		Detectors: notProcessedDetector,
	}
}

// detectContent downloads a layer and detects all features and namespaces.
func detectContent(imageFormat, name, path string, headers map[string]string, toProcess database.Processors) (namespaces []database.Namespace, featureVersions []database.Feature, err error) {
	log.WithFields(log.Fields{"Hash": name}).Debug("Process Layer")
	totalRequiredFiles := append(featurefmt.RequiredFilenames(toProcess.Listers), featurens.RequiredFilenames(toProcess.Detectors)...)
	files, err := imagefmt.Extract(imageFormat, path, headers, totalRequiredFiles)
	if err != nil {
		log.WithError(err).WithFields(log.Fields{
			logLayerName: name,
			"path":       cleanURL(path),
		}).Error("failed to extract data from path")
		return
	}

	namespaces, err = featurens.Detect(files, toProcess.Detectors)
	if err != nil {
		return
	}

	if len(featureVersions) > 0 {
		log.WithFields(log.Fields{logLayerName: name, "count": len(namespaces)}).Debug("detected layer namespaces")
	}

	featureVersions, err = featurefmt.ListFeatures(files, toProcess.Listers)
	if err != nil {
		return
	}

	if len(featureVersions) > 0 {
		log.WithFields(log.Fields{logLayerName: name, "count": len(featureVersions)}).Debug("detected layer features")
	}

	return
}
