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

package clair

import (
	"errors"
	"sync"

	"github.com/deckarep/golang-set"
	log "github.com/sirupsen/logrus"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/ext/featurefmt"
	"github.com/coreos/clair/ext/featurens"
	"github.com/coreos/clair/ext/imagefmt"
	"github.com/coreos/clair/pkg/commonerr"
	"github.com/coreos/clair/pkg/strutil"
	"github.com/coreos/clair/pkg/tarutil"
)

var (
	// ErrUnsupported is the error that should be raised when an OS or package
	// manager is not supported.
	ErrUnsupported = commonerr.NewBadRequestError("worker: OS and/or package manager are not supported")

	// EnabledDetectors are detectors to be used to scan the layers.
	EnabledDetectors []database.Detector
)

// LayerRequest represents all information necessary to download and process a
// layer.
type LayerRequest struct {
	Hash    string
	Path    string
	Headers map[string]string
}

type processResult struct {
	existingLayer   *database.Layer
	newLayerContent *database.Layer
	err             error
}

// processRequest stores parameters used for processing a layer.
type processRequest struct {
	LayerRequest

	existingLayer *database.Layer
	detectors     []database.Detector
}

type introducedFeature struct {
	feature    database.AncestryFeature
	layerIndex int
}

// processRequests in parallel processes a set of requests for unique set of layers
// and returns sets of unique namespaces, features and layers to be inserted
// into the database.
func processRequests(imageFormat string, toDetect map[string]*processRequest) (map[string]*processResult, error) {
	wg := &sync.WaitGroup{}
	wg.Add(len(toDetect))

	results := map[string]*processResult{}
	for i := range toDetect {
		results[i] = nil
	}

	for i := range toDetect {
		result := processResult{}
		results[i] = &result
		go func(req *processRequest, res *processResult) {
			*res = *detectContent(imageFormat, req)
			wg.Done()
		}(toDetect[i], &result)
	}

	wg.Wait()
	errs := []error{}
	for _, r := range results {
		errs = append(errs, r.err)
	}

	if err := commonerr.CombineErrors(errs...); err != nil {
		return nil, err
	}

	return results, nil
}

func getProcessRequest(datastore database.Datastore, req LayerRequest) (preq *processRequest, err error) {
	layer, ok, err := database.FindLayerAndRollback(datastore, req.Hash)
	if err != nil {
		return
	}

	if !ok {
		log.WithField("layer", req.Hash).Debug("found no existing layer in database")
		preq = &processRequest{
			LayerRequest:  req,
			existingLayer: &database.Layer{Hash: req.Hash},
			detectors:     EnabledDetectors,
		}
	} else {
		log.WithFields(log.Fields{
			"layer":           layer.Hash,
			"detectors":       layer.By,
			"feature count":   len(layer.Features),
			"namespace count": len(layer.Namespaces),
		}).Debug("found existing layer in database")

		preq = &processRequest{
			LayerRequest:  req,
			existingLayer: &layer,
			detectors:     database.DiffDetectors(EnabledDetectors, layer.By),
		}
	}

	return
}

func persistProcessResult(datastore database.Datastore, results map[string]*processResult) error {
	features := []database.Feature{}
	namespaces := []database.Namespace{}
	for _, r := range results {
		features = append(features, r.newLayerContent.GetFeatures()...)
		namespaces = append(namespaces, r.newLayerContent.GetNamespaces()...)
	}

	features = database.DeduplicateFeatures(features...)
	namespaces = database.DeduplicateNamespaces(namespaces...)
	if err := database.PersistNamespacesAndCommit(datastore, namespaces); err != nil {
		return err
	}

	if err := database.PersistFeaturesAndCommit(datastore, features); err != nil {
		return err
	}

	for _, layer := range results {
		if err := database.PersistPartialLayerAndCommit(datastore, layer.newLayerContent); err != nil {
			return err
		}
	}

	return nil
}

// processLayers processes a set of post layer requests, stores layers and
// returns an ordered list of processed layers with detected features and
// namespaces.
func processLayers(datastore database.Datastore, imageFormat string, requests []LayerRequest) ([]database.Layer, error) {
	var (
		reqMap = make(map[string]*processRequest)
		err    error
	)

	for _, r := range requests {
		reqMap[r.Hash], err = getProcessRequest(datastore, r)
		if err != nil {
			return nil, err
		}
	}

	results, err := processRequests(imageFormat, reqMap)
	if err != nil {
		return nil, err
	}

	if err := persistProcessResult(datastore, results); err != nil {
		return nil, err
	}

	completeLayers := getProcessResultLayers(results)
	layers := make([]database.Layer, 0, len(requests))
	for _, r := range requests {
		layers = append(layers, completeLayers[r.Hash])
	}

	return layers, nil
}

func getProcessResultLayers(results map[string]*processResult) map[string]database.Layer {
	layers := map[string]database.Layer{}
	for name, r := range results {
		layers[name] = *database.MergeLayers(r.existingLayer, r.newLayerContent)
	}

	return layers
}

func isAncestryProcessed(datastore database.Datastore, name string) (bool, error) {
	ancestry, ok, err := database.FindAncestryAndRollback(datastore, name)
	if err != nil || !ok {
		return ok, err
	}

	return len(database.DiffDetectors(EnabledDetectors, ancestry.By)) == 0, nil
}

// ProcessAncestry downloads and scans an ancestry if it's not scanned by all
// enabled processors in this instance of Clair.
func ProcessAncestry(datastore database.Datastore, imageFormat, name string, layerRequest []LayerRequest) error {
	var (
		err    error
		ok     bool
		layers []database.Layer
	)

	if name == "" {
		return commonerr.NewBadRequestError("could not process a layer which does not have a name")
	}

	if imageFormat == "" {
		return commonerr.NewBadRequestError("could not process a layer which does not have a format")
	}

	log.WithField("ancestry", name).Debug("start processing ancestry...")
	if ok, err = isAncestryProcessed(datastore, name); err != nil {
		log.WithError(err).Error("could not determine if ancestry is processed")
		return err
	} else if ok {
		log.WithField("ancestry", name).Debug("ancestry is already processed")
		return nil
	}

	if layers, err = processLayers(datastore, imageFormat, layerRequest); err != nil {
		return err
	}

	return processAncestry(datastore, name, layers)
}

func processAncestry(datastore database.Datastore, name string, layers []database.Layer) error {
	var (
		ancestry = database.Ancestry{Name: name}
		err      error
	)

	ancestry.Layers, ancestry.By, err = computeAncestryLayers(layers)
	if err != nil {
		return err
	}

	ancestryFeatures := database.GetAncestryFeatures(ancestry)
	log.WithFields(log.Fields{
		"ancestry":       name,
		"processed by":   EnabledDetectors,
		"features count": len(ancestryFeatures),
		"layer count":    len(ancestry.Layers),
	}).Debug("compute ancestry features")

	if err := database.PersistNamespacedFeaturesAndCommit(datastore, ancestryFeatures); err != nil {
		log.WithField("ancestry", name).WithError(err).Error("could not persist namespaced features for ancestry")
		return err
	}

	if err := database.CacheRelatedVulnerabilityAndCommit(datastore, ancestryFeatures); err != nil {
		log.WithField("ancestry", name).WithError(err).Error("failed to cache feature related vulnerability")
		return err
	}

	if err := database.UpsertAncestryAndCommit(datastore, ancestry); err != nil {
		log.WithField("ancestry", name).WithError(err).Error("could not upsert ancestry")
		return err
	}

	return nil
}

func getCommonDetectors(layers []database.Layer) mapset.Set {
	// find the common detector for all layers and filter the namespaces and
	// features based on that.
	commonDetectors := mapset.NewSet()
	for _, d := range layers[0].By {
		commonDetectors.Add(d)
	}

	for _, l := range layers {
		detectors := mapset.NewSet()
		for _, d := range l.By {
			detectors.Add(d)
		}

		commonDetectors = commonDetectors.Intersect(detectors)
	}

	return commonDetectors
}

// computeAncestryLayers computes ancestry's layers along with what features are
// introduced.
func computeAncestryLayers(layers []database.Layer) ([]database.AncestryLayer, []database.Detector, error) {
	if len(layers) == 0 {
		return nil, nil, nil
	}

	commonDetectors := getCommonDetectors(layers)
	// version format -> namespace
	namespaces := map[string]database.LayerNamespace{}
	// version format -> feature ID -> feature
	features := map[string]map[string]introducedFeature{}
	ancestryLayers := []database.AncestryLayer{}
	for index, layer := range layers {
		initializedLayer := database.AncestryLayer{Hash: layer.Hash}
		ancestryLayers = append(ancestryLayers, initializedLayer)

		// Precondition: namespaces and features contain the result from union
		// of all parents.
		for _, ns := range layer.Namespaces {
			if !commonDetectors.Contains(ns.By) {
				continue
			}

			namespaces[ns.VersionFormat] = ns
		}

		// version format -> feature ID -> feature
		currentFeatures := map[string]map[string]introducedFeature{}
		for _, f := range layer.Features {
			if !commonDetectors.Contains(f.By) {
				continue
			}

			if ns, ok := namespaces[f.VersionFormat]; ok {
				var currentMap map[string]introducedFeature
				if currentMap, ok = currentFeatures[f.VersionFormat]; !ok {
					currentFeatures[f.VersionFormat] = make(map[string]introducedFeature)
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
					currentMap[f.Name+":"+f.Version] = introducedFeature{
						feature: database.AncestryFeature{
							NamespacedFeature: database.NamespacedFeature{
								Feature:   f.Feature,
								Namespace: ns.Namespace,
							},
							NamespaceBy: ns.By,
							FeatureBy:   f.By,
						},
						layerIndex: index,
					}
				}

			} else {
				return nil, nil, errors.New("No corresponding version format")
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

	for _, featureMap := range features {
		for _, feature := range featureMap {
			ancestryLayers[feature.layerIndex].Features = append(
				ancestryLayers[feature.layerIndex].Features,
				feature.feature,
			)
		}
	}

	detectors := make([]database.Detector, 0, commonDetectors.Cardinality())
	for d := range commonDetectors.Iter() {
		detectors = append(detectors, d.(database.Detector))
	}

	return ancestryLayers, detectors, nil
}

func extractRequiredFiles(imageFormat string, req *processRequest) (tarutil.FilesMap, error) {
	requiredFiles := append(featurefmt.RequiredFilenames(req.detectors), featurens.RequiredFilenames(req.detectors)...)
	if len(requiredFiles) == 0 {
		log.WithFields(log.Fields{
			"layer":     req.Hash,
			"detectors": req.detectors,
		}).Info("layer requires no file to extract")
		return make(tarutil.FilesMap), nil
	}

	files, err := imagefmt.Extract(imageFormat, req.Path, req.Headers, requiredFiles)
	if err != nil {
		log.WithError(err).WithFields(log.Fields{
			"layer": req.Hash,
			"path":  strutil.CleanURL(req.Path),
		}).Error("failed to extract data from path")
		return nil, err
	}

	return files, err
}

// detectContent downloads a layer and detects all features and namespaces.
func detectContent(imageFormat string, req *processRequest) (res *processResult) {
	var (
		files tarutil.FilesMap
		layer = database.Layer{Hash: req.Hash, By: req.detectors}
	)

	res = &processResult{req.existingLayer, &layer, nil}
	log.WithFields(log.Fields{
		"layer":     req.Hash,
		"detectors": req.detectors,
	}).Info("detecting layer content...")

	files, res.err = extractRequiredFiles(imageFormat, req)
	if res.err != nil {
		return
	}

	if layer.Namespaces, res.err = featurens.Detect(files, req.detectors); res.err != nil {
		return
	}

	if layer.Features, res.err = featurefmt.ListFeatures(files, req.detectors); res.err != nil {
		return
	}

	log.WithFields(log.Fields{
		"layer":           req.Hash,
		"detectors":       req.detectors,
		"namespace count": len(layer.Namespaces),
		"feature count":   len(layer.Features),
	}).Info("processed layer")

	return
}

// InitWorker initializes the worker.
func InitWorker(datastore database.Datastore) {
	if len(EnabledDetectors) == 0 {
		log.Warn("no enabled detector, and therefore, no ancestry will be processed.")
		return
	}

	tx, err := datastore.Begin()
	if err != nil {
		log.WithError(err).Fatal("cannot connect to database to initialize worker")
	}

	defer tx.Rollback()
	if err := tx.PersistDetectors(EnabledDetectors); err != nil {
		log.WithError(err).Fatal("cannot insert detectors to initialize worker")
	}

	if err := tx.Commit(); err != nil {
		log.WithError(err).Fatal("cannot commit detector changes to initialize worker")
	}
}
