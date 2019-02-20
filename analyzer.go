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
	"context"

	log "github.com/sirupsen/logrus"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/ext/featurefmt"
	"github.com/coreos/clair/ext/featurens"
	"github.com/coreos/clair/ext/imagefmt"
)

// AnalyzeError represents an failure when analyzing layer or constructing
// ancestry.
type AnalyzeError string

func (e AnalyzeError) Error() string {
	return string(e)
}

var (
	// StorageError represents an analyze error caused by the storage
	StorageError = AnalyzeError("failed to query the database.")
	// RetrieveBlobError represents an analyze error caused by failure of
	// downloading or extracting layer blobs.
	RetrieveBlobError = AnalyzeError("failed to download layer blob.")
	// ExtractBlobError represents an analyzer error caused by failure of
	// extracting a layer blob by imagefmt.
	ExtractBlobError = AnalyzeError("failed to extract files from layer blob.")
	// FeatureDetectorError is an error caused by failure of feature listing by
	// featurefmt.
	FeatureDetectorError = AnalyzeError("failed to scan feature from layer blob files.")
	// NamespaceDetectorError is an error caused by failure of namespace
	// detection by featurens.
	NamespaceDetectorError = AnalyzeError("failed to scan namespace from layer blob files.")
)

// AnalyzeLayer retrieves the clair layer with all extracted features and namespaces.
// If a layer is already scanned by all enabled detectors in the Clair instance, it returns directly.
// Otherwise, it re-download the layer blob and scan the features and namespaced again.
func AnalyzeLayer(ctx context.Context, store database.Datastore, blobSha256 string, blobFormat string, downloadURI string, downloadHeaders map[string]string) (*database.Layer, error) {
	layer, found, err := database.FindLayerAndRollback(store, blobSha256)
	logFields := log.Fields{"layer.Hash": blobSha256}
	if err != nil {
		log.WithError(err).WithFields(logFields).Error("failed to find layer in the storage")
		return nil, StorageError
	}

	var scannedBy []database.Detector
	if found {
		scannedBy = layer.By
	}

	// layer will be scanned by detectors not scanned the layer already.
	toScan := database.DiffDetectors(EnabledDetectors(), scannedBy)
	if len(toScan) != 0 {
		log.WithFields(logFields).Debug("scan layer blob not already scanned")
		newLayerScanResult := &database.Layer{Hash: blobSha256, By: toScan}
		blob, err := retrieveLayerBlob(ctx, downloadURI, downloadHeaders)
		if err != nil {
			log.WithError(err).WithFields(logFields).Error("failed to retrieve layer blob")
			return nil, RetrieveBlobError
		}

		defer func() {
			if err := blob.Close(); err != nil {
				log.WithFields(logFields).Error("failed to close layer blob reader")
			}
		}()

		files := append(featurefmt.RequiredFilenames(toScan), featurens.RequiredFilenames(toScan)...)
		fileMap, err := imagefmt.Extract(blobFormat, blob, files)
		if err != nil {
			log.WithFields(logFields).WithError(err).Error("failed to extract layer blob")
			return nil, ExtractBlobError
		}

		newLayerScanResult.Features, err = featurefmt.ListFeatures(fileMap, toScan)
		if err != nil {
			log.WithFields(logFields).WithError(err).Error("failed to detect features")
			return nil, FeatureDetectorError
		}

		newLayerScanResult.Namespaces, err = featurens.Detect(fileMap, toScan)
		if err != nil {
			log.WithFields(logFields).WithError(err).Error("failed to detect namespaces")
			return nil, NamespaceDetectorError
		}

		if err = saveLayerChange(store, newLayerScanResult); err != nil {
			log.WithFields(logFields).WithError(err).Error("failed to store layer change")
			return nil, StorageError
		}

		layer = database.MergeLayers(layer, newLayerScanResult)
	} else {
		log.WithFields(logFields).Debug("found scanned layer blob")
	}

	return layer, nil
}

// EnabledDetectors retrieves a list of all detectors installed in the Clair
// instance.
func EnabledDetectors() []database.Detector {
	return append(featurefmt.ListListers(), featurens.ListDetectors()...)
}

// RegisterConfiguredDetectors populates the database with registered detectors.
func RegisterConfiguredDetectors(store database.Datastore) {
	if err := database.PersistDetectorsAndCommit(store, EnabledDetectors()); err != nil {
		panic("failed to initialize Clair analyzer")
	}
}

func saveLayerChange(store database.Datastore, layer *database.Layer) error {
	if err := database.PersistFeaturesAndCommit(store, layer.GetFeatures()); err != nil {
		return err
	}

	if err := database.PersistNamespacesAndCommit(store, layer.GetNamespaces()); err != nil {
		return err
	}

	if err := database.PersistPartialLayerAndCommit(store, layer); err != nil {
		return err
	}

	return nil
}
