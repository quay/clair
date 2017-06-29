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
	"regexp"

	log "github.com/sirupsen/logrus"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/ext/featurefmt"
	"github.com/coreos/clair/ext/featurens"
	"github.com/coreos/clair/ext/imagefmt"
	"github.com/coreos/clair/pkg/commonerr"
	"github.com/coreos/clair/pkg/tarutil"
)

const (
	// Version (integer) represents the worker version.
	// Increased each time the engine changes.
	Version      = 3
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
)

// cleanURL removes all parameters from an URL.
func cleanURL(str string) string {
	return urlParametersRegexp.ReplaceAllString(str, "")
}

// ProcessLayer detects the Namespace of a layer, the features it adds/removes,
// and then stores everything in the database.
//
// TODO(Quentin-M): We could have a goroutine that looks for layers that have
// been analyzed with an older engine version and that processes them.
func ProcessLayer(datastore database.Datastore, imageFormat, name, parentName, path string, headers map[string]string, namespaceName string) error {
	// Verify parameters.
	if name == "" {
		return commonerr.NewBadRequestError("could not process a layer which does not have a name")
	}

	if path == "" {
		return commonerr.NewBadRequestError("could not process a layer which does not have a path")
	}

	if imageFormat == "" {
		return commonerr.NewBadRequestError("could not process a layer which does not have a format")
	}

	log.WithFields(log.Fields{logLayerName: name, "path": cleanURL(path), "engine version": Version, "parent layer": parentName, "format": imageFormat}).Debug("processing layer")

	// Check to see if the layer is already in the database.
	layer, err := datastore.FindLayer(name, false, false)
	if err != nil && err != commonerr.ErrNotFound {
		return err
	}

	if err == commonerr.ErrNotFound {
		// New layer case.
		layer = database.Layer{Name: name, EngineVersion: Version}

		// Retrieve the parent if it has one.
		// We need to get it with its Features in order to diff them.
		if parentName != "" {
			parent, err := datastore.FindLayer(parentName, true, false)
			if err != nil && err != commonerr.ErrNotFound {
				return err
			}
			if err == commonerr.ErrNotFound {
				log.WithFields(log.Fields{logLayerName: name, "parent layer": parentName}).Warning("the parent layer is unknown. it must be processed first")
				return ErrParentUnknown
			}
			layer.Parent = &parent
		}
	} else {
		// The layer is already in the database, check if we need to update it.
		if layer.EngineVersion >= Version {
			log.WithFields(log.Fields{logLayerName: name, "past engine version": layer.EngineVersion, "current engine version": Version}).Debug("layer content has already been processed in the past with older engine. skipping analysis")
			return nil
		}
		log.WithFields(log.Fields{logLayerName: name, "past engine version": layer.EngineVersion, "current engine version": Version}).Debug("layer content has already been processed in the past with older engine. analyzing again")
	}

	// Check to see if the user's provided Namespace exists
	var namespace *database.Namespace
	if namespaceName != "" {
		namespace, err = datastore.GetNamespace(namespaceName)
		if err != nil {
			if err == commonerr.ErrNotFound {
				return commonerr.NewBadRequestError("could not find provided namespace")
			}
			return err
		}
	}
	// Analyze the content.
	layer.Namespace, layer.Features, err = detectContent(imageFormat, name, path, headers, layer.Parent, namespace)
	if err != nil {
		return err
	}

	return datastore.InsertLayer(layer)
}

// detectContent downloads a layer's archive and extracts its Namespace and
// Features.
func detectContent(imageFormat, name, path string, headers map[string]string, parent *database.Layer, ns *database.Namespace) (namespace *database.Namespace, featureVersions []database.FeatureVersion, err error) {
	totalRequiredFiles := append(featurefmt.RequiredFilenames(), featurens.RequiredFilenames()...)
	files, err := imagefmt.Extract(imageFormat, path, headers, totalRequiredFiles)
	if err != nil {
		log.WithError(err).WithFields(log.Fields{logLayerName: name, "path": cleanURL(path)}).Error("failed to extract data from path")
		return
	}

	namespace, err = detectNamespace(name, files, parent)
	if err != nil {
		return
	}

	if namespace == nil && ns != nil {
		log.WithFields(log.Fields{logLayerName: name, "namespace provided by user": ns.Name}).Debug("detected namespace")
		namespace = ns
	}

	// Detect features.
	featureVersions, err = detectFeatureVersions(name, files, namespace, parent)
	if err != nil {
		return
	}
	if len(featureVersions) > 0 {
		log.WithFields(log.Fields{logLayerName: name, "feature count": len(featureVersions)}).Debug("detected features")
	}

	return
}

func detectNamespace(name string, files tarutil.FilesMap, parent *database.Layer) (namespace *database.Namespace, err error) {
	namespace, err = featurens.Detect(files)
	if err != nil {
		return
	}
	if namespace != nil {
		log.WithFields(log.Fields{logLayerName: name, "detected namespace": namespace.Name}).Debug("detected namespace")
		return
	}

	// Fallback to the parent's namespace.
	if parent != nil {
		namespace = parent.Namespace
		if namespace != nil {
			log.WithFields(log.Fields{logLayerName: name, "detected namespace": namespace.Name}).Debug("detected namespace (from parent)")
			return
		}
	}

	return
}

func detectFeatureVersions(name string, files tarutil.FilesMap, namespace *database.Namespace, parent *database.Layer) (features []database.FeatureVersion, err error) {
	// TODO(Quentin-M): We need to pass the parent image to DetectFeatures because it's possible that
	// some detectors would need it in order to produce the entire feature list (if they can only
	// detect a diff). Also, we should probably pass the detected namespace so detectors could
	// make their own decision.
	features, err = featurefmt.ListFeatures(files)
	if err != nil {
		return
	}

	// If there are no FeatureVersions, use parent's FeatureVersions if possible.
	// TODO(Quentin-M): We eventually want to give the choice to each detectors to use none/some of
	// their parent's FeatureVersions. It would be useful for detectors that can't find their entire
	// result using one Layer.
	if len(features) == 0 && parent != nil {
		features = parent.Features
		return
	}

	// Build a map of the namespaces for each FeatureVersion in our parent layer.
	parentFeatureNamespaces := make(map[string]database.Namespace)
	if parent != nil {
		for _, parentFeature := range parent.Features {
			parentFeatureNamespaces[parentFeature.Feature.Name+":"+parentFeature.Version] = parentFeature.Feature.Namespace
		}
	}

	// Ensure that each FeatureVersion has an associated Namespace.
	for i, feature := range features {
		if feature.Feature.Namespace.Name != "" {
			// There is a Namespace associated.
			continue
		}

		if parentFeatureNamespace, ok := parentFeatureNamespaces[feature.Feature.Name+":"+feature.Version]; ok {
			// The FeatureVersion is present in the parent layer; associate with their Namespace.
			features[i].Feature.Namespace = parentFeatureNamespace
			continue
		}

		if namespace != nil {
			// The Namespace has been detected in this layer; associate it.
			features[i].Feature.Namespace = *namespace
			continue
		}

		log.WithFields(log.Fields{"feature name": feature.Feature.Name, "feature version": feature.Version, logLayerName: name}).Warning("Namespace unknown")
		err = ErrUnsupported
		return
	}

	return
}
