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

// Package worker implements the logic to extract useful informations from a
// container layer and store it in the database.
package worker

import (
	"github.com/coreos/pkg/capnslog"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/utils"
	cerrors "github.com/coreos/clair/utils/errors"
	"github.com/coreos/clair/worker/detectors"
)

const (
	// Version (integer) represents the worker version.
	// Increased each time the engine changes.
	Version = 2

	// maxFileSize is the maximum size of a single file we should extract.
	maxFileSize = 200 * 1024 * 1024 // 200 MiB
)

var (
	log = capnslog.NewPackageLogger("github.com/coreos/clair", "worker")

	// ErrUnsupported is the error that should be raised when an OS or package
	// manager is not supported.
	ErrUnsupported = cerrors.NewBadRequestError("worker: OS and/or package manager are not supported")

	// ErrParentUnknown is the error that should be raised when a parent layer
	// has yet to be processed for the current layer.
	ErrParentUnknown = cerrors.NewBadRequestError("worker: parent layer is unknown, it must be processed first")
)

// Process detects the Namespaces of a layer, the features it adds/removes, and
// then stores everything in the database.
// TODO(Quentin-M): We could have a goroutine that looks for layers that have been analyzed with an
// older engine version and that processes them.
func Process(datastore database.Datastore, imageFormat, name, parentName, path string, headers map[string]string) error {
	// Verify parameters.
	if name == "" {
		return cerrors.NewBadRequestError("could not process a layer which does not have a name")
	}

	if path == "" {
		return cerrors.NewBadRequestError("could not process a layer which does not have a path")
	}

	if imageFormat == "" {
		return cerrors.NewBadRequestError("could not process a layer which does not have a format")
	}

	log.Debugf("layer %s: processing (Location: %s, Engine version: %d, Parent: %s, Format: %s)",
		name, utils.CleanURL(path), Version, parentName, imageFormat)

	// Check to see if the layer is already in the database.
	layer, err := datastore.FindLayer(name, false, false)
	if err != nil && err != cerrors.ErrNotFound {
		return err
	}

	if err == cerrors.ErrNotFound {
		// New layer case.
		layer = database.Layer{Name: name, EngineVersion: Version}

		// Retrieve the parent if it has one.
		// We need to get it with its Features in order to diff them.
		if parentName != "" {
			parent, err := datastore.FindLayer(parentName, true, false)
			if err != nil && err != cerrors.ErrNotFound {
				return err
			}
			if err == cerrors.ErrNotFound {
				log.Warningf("layer %s: the parent layer (%s) is unknown. it must be processed first", name,
					parentName)
				return ErrParentUnknown
			}
			layer.Parent = &parent
		}
	} else {
		// The layer is already in the database, check if we need to update it.
		if layer.EngineVersion >= Version {
			log.Debugf(`layer %s: layer content has already been processed in the past with engine %d.
        Current engine is %d. skipping analysis`, name, layer.EngineVersion, Version)
			return nil
		}

		log.Debugf(`layer %s: layer content has been analyzed in the past with engine %d. Current
      engine is %d. analyzing again`, name, layer.EngineVersion, Version)
	}

	// Analyze the content.
	layer.Namespaces, layer.Features, err = detectContent(imageFormat, name, path, headers, layer.Parent)
	if err != nil {
		return err
	}

	return datastore.InsertLayer(layer)
}

// detectContent downloads a layer's archive and extracts its Namespaces and Features.
func detectContent(imageFormat, name, path string, headers map[string]string, parent *database.Layer) (namespaces []database.Namespace, features []database.FeatureVersion, err error) {
	data, err := detectors.DetectData(imageFormat, path, headers, append(detectors.GetRequiredFilesFeatures(),
		detectors.GetRequiredFilesNamespace()...), maxFileSize)
	if err != nil {
		log.Errorf("layer %s: failed to extract data from %s: %s", name, utils.CleanURL(path), err)
		return
	}

	// Detect namespace.
	namespaces, err = detectNamespaces(name, data, parent)
	if err != nil {
		return
	}
	if len(namespaces) > 0 {
		log.Debugf("layer %s: %d Namespaces detected: ", name, len(namespaces))
		for _, namespace := range namespaces {
			log.Debugf("\t%s", namespace.Name)
		}
	} else {
		log.Debugf("layer %s: Package System is unknown.", name)
	}

	// Detect features.
	features, err = detectors.DetectFeatures(data, namespaces)
	if err != nil {
		return
	}
	if len(features) > 0 {
		log.Debugf("layer %s: detected %d features", name, len(features))
	}

	return
}

func detectNamespaces(name string, data map[string][]byte, parent *database.Layer) (namespaces []database.Namespace, err error) {
	namespaces = detectors.DetectNamespaces(data)

	// Inherit the non-detected namespace from its parent
	if parent != nil {
		mapNamespaces := make(map[string]database.Namespace)

		// Layer's namespaces has high priority than its parent.
		for _, n := range namespaces {
			mapNamespaces[n.Name] = n
		}

		for _, pn := range parent.Namespaces {
			if _, ok := mapNamespaces[pn.Name]; !ok {
				mapNamespaces[pn.Name] = pn
				log.Debugf("layer %s: detected namespace %q (from parent)", name, pn.Name)
			}
		}

		namespaces = []database.Namespace{}
		for _, namespace := range mapNamespaces {
			namespaces = append(namespaces, namespace)
		}
	}

	return
}
