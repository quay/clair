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
	"errors"
	"strings"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/utils"
	cerrors "github.com/coreos/clair/utils/errors"
	"github.com/coreos/clair/worker/detectors"
	"github.com/coreos/pkg/capnslog"
)

const (
	// Version (integer) represents the worker version.
	// Increased each time the engine changes.
	Version = 1

	// maxFileSize is the maximum size of a single file we should extract.
	maxFileSize = 200 * 1024 * 1024 // 200 MiB
)

var (
	log = capnslog.NewPackageLogger("github.com/coreos/clair", "worker")

	// ErrUnsupported is the error that should be raised when an OS or package
	// manager is not supported.
	ErrUnsupported = errors.New("worker: OS and/or package manager are not supported")

	// ErrParentUnknown is the error that should be raised when a parent layer
	// has yet to be processed for the current layer.
	ErrParentUnknown = errors.New("worker: parent layer is unknown, it must be processed first")

	// SupportedOS is the list of operating system names that the worker supports.
	SupportedOS = []string{"debian", "ubuntu", "centos"}

	// SupportedImageFormat is the list of image formats that the worker supports.
	SupportedImageFormat = []string{"Docker", "ACI"}
)

// Process detects the OS of a layer, the packages it installs/removes, and
// then stores everything in the database.
func Process(ID, parentID, path string, imageFormat string) error {
	if ID == "" {
		return cerrors.NewBadRequestError("could not process a layer which does not have ID")
	}
	if path == "" {
		return cerrors.NewBadRequestError("could not process a layer which does not have a path")
	}
	if imageFormat == "" {
		return cerrors.NewBadRequestError("could not process a layer which does not have a specified format")
	} else {
		isSupported := false
		for _, format := range SupportedImageFormat {
			if strings.EqualFold(imageFormat, format) {
				isSupported = true
				break
			}
		}
		if !isSupported {
			return cerrors.NewBadRequestError("could not process a layer which does not have a supported format")
		}
	}

	log.Debugf("layer %s: processing (Location: %s, Engine version: %d, Parent: %s, Format: %s)", ID, utils.CleanURL(path), Version, parentID, imageFormat)

	// Check to see if the layer is already in the database.
	layer, err := database.FindOneLayerByID(ID, []string{database.FieldLayerEngineVersion})
	if err != nil && err != cerrors.ErrNotFound {
		return err
	}

	var parent *database.Layer

	if layer != nil {
		// The layer is already in the database, check if we need to update it.
		if layer.EngineVersion >= Version {
			log.Debugf("layer %s: layer content has already been processed in the past with engine %d. Current engine is %d. skipping analysis", ID, layer.EngineVersion, Version)
			return nil
		}

		log.Debugf("layer %s: layer content has been analyzed in the past with engine %d. Current engine is %d. analyzing again", ID, layer.EngineVersion, Version)
	} else {
		// The layer is a new one, create a base struct that we will fill.
		layer = &database.Layer{ID: ID, EngineVersion: Version}

		// Check to make sure that the parent's layer has already been processed.
		if parentID != "" {
			parent, err = database.FindOneLayerByID(parentID, []string{database.FieldLayerOS, database.FieldLayerPackages, database.FieldLayerPackages})
			if err != nil && err != cerrors.ErrNotFound {
				return err
			}
			if parent == nil {
				log.Warningf("layer %s: the parent layer (%s) is unknown. it must be processed first", ID, parentID)
				return ErrParentUnknown
			}
			layer.ParentNode = parent.GetNode()
		}
	}

	// Analyze the content.
	layer.OS, layer.InstalledPackagesNodes, layer.RemovedPackagesNodes, err = detectContent(ID, path, parent, imageFormat)
	if err != nil {
		return err
	}

	return database.InsertLayer(layer)
}

// detectContent downloads a layer's archive, extracts info from it and returns
// an updated Layer struct.
//
// If parent is not nil, database.FieldLayerOS, database.FieldLayerPackages fields must be
// has been selectioned.
func detectContent(ID, path string, parent *database.Layer, imageFormat string) (OS string, installedPackagesNodes, removedPackagesNodes []string, err error) {
	data, err := getLayerData(path, imageFormat)
	if err != nil {
		log.Errorf("layer %s: failed to extract data from %s: %s", ID, utils.CleanURL(path), err)
		return
	}

	OS, err = detectOS(data, parent)
	if err != nil {
		return
	}
	if OS != "" {
		log.Debugf("layer %s: OS is %s.", ID, OS)
	} else {
		log.Debugf("layer %s: OS is unknown.", ID)
	}

	packageList, err := detectors.DetectPackages(data)
	if err != nil {
		log.Errorf("layer %s: package list could not be determined: %s", ID, err)
		return
	}

	// If there are any packages, that layer modified the package list.
	if len(packageList) > 0 {
		// It is possible that the OS could not be detected, in the case of a
		// first layer setting MAINTAINER only for instance. However, if the OS
		// is unknown and packages are detected, we have to return an error.
		if OS == "" {
			log.Errorf("layer %s: OS is unknown but %d packages have been detected", ID, len(packageList))
			err = ErrUnsupported
			return
		}

		// If the layer has no parent, it can only add packages, not remove them.
		if parent == nil {
			// Build a list of the layer packages' node values.
			var installedPackages []*database.Package
			for _, p := range packageList {
				p.OS = OS
				installedPackages = append(installedPackages, p)
			}

			// Insert that list into the database.
			err = database.InsertPackages(installedPackages)
			if err != nil {
				return
			}

			// Set the InstalledPackageNodes field on content.
			for _, p := range installedPackages {
				if p.Node != "" {
					installedPackagesNodes = append(installedPackagesNodes, p.Node)
				}
			}
		} else {
			installedPackagesNodes, removedPackagesNodes, err = detectAndInsertInstalledAndRemovedPackages(OS, packageList, parent)
			if err != nil {
				return
			}
		}
	}

	log.Debugf("layer %s: detected %d packages: installs %d and removes %d packages", ID, len(packageList), len(installedPackagesNodes), len(removedPackagesNodes))
	return
}

// getLayerData downloads/opens a layer archive and extracts it into memory.
func getLayerData(path string, imageFormat string) (data map[string][]byte, err error) {
	data, err = detectors.DetectData(path, imageFormat, append(detectors.GetRequiredFilesPackages(), detectors.GetRequiredFilesOS()...), maxFileSize)
	if err != nil {
		return nil, err
	}

	return
}

func detectOS(data map[string][]byte, parent *database.Layer) (detectedOS string, err error) {
	detectedOS = detectors.DetectOS(data)

	// Attempt to detect the OS from the parent layer.
	if detectedOS == "" && parent != nil {
		detectedOS, err = parent.OperatingSystem()
		if err != nil {
			return "", err
		}
	}

	// If the detectedOS is not in the supported OS list, the OS is unsupported.
	if detectedOS != "" {
		isSupported := false
		for _, osPrefix := range SupportedOS {
			if strings.HasPrefix(detectedOS, osPrefix) {
				isSupported = true
				break
			}
		}
		if !isSupported {
			return "", ErrUnsupported
		}
	}

	return
}

// detectAndInsertInstalledAndRemovedPackages finds the installed and removed
// package nodes and inserts the installed packages into the database.
func detectAndInsertInstalledAndRemovedPackages(detectedOS string, packageList []*database.Package, parent *database.Layer) (installedNodes, removedNodes []string, err error) {
	// Get the parent layer's packages.
	parentPackageNodes, err := parent.AllPackages()
	if err != nil {
		return nil, nil, err
	}
	parentPackages, err := database.FindAllPackagesByNodes(parentPackageNodes, []string{database.FieldPackageName, database.FieldPackageVersion})
	if err != nil {
		return nil, nil, err
	}

	// Map detected packages (name:version) string to packages.
	packagesNVMapToPackage := make(map[string]*database.Package)
	for _, p := range packageList {
		packagesNVMapToPackage[p.Name+":"+p.Version.String()] = p
	}

	// Map parent's packages (name:version) string to nodes.
	parentPackagesNVMapToNodes := make(map[string]string)
	for _, p := range parentPackages {
		parentPackagesNVMapToNodes[p.Name+":"+p.Version.String()] = p.Node
	}

	// Build a list of the parent layer's packages' node values.
	var parentPackagesNV []string
	for _, p := range parentPackages {
		parentPackagesNV = append(parentPackagesNV, p.Name+":"+p.Version.String())
	}

	// Build a list of the layer packages' node values.
	var layerPackagesNV []string
	for _, p := range packageList {
		layerPackagesNV = append(layerPackagesNV, p.Name+":"+p.Version.String())
	}

	// Calculate the installed and removed packages.
	removedPackagesNV := utils.CompareStringLists(parentPackagesNV, layerPackagesNV)
	installedPackagesNV := utils.CompareStringLists(layerPackagesNV, parentPackagesNV)

	// Build a list of all the installed packages.
	var installedPackages []*database.Package
	for _, nv := range installedPackagesNV {
		p, _ := packagesNVMapToPackage[nv]
		p.OS = detectedOS
		installedPackages = append(installedPackages, p)
	}

	// Insert that list into the database.
	err = database.InsertPackages(installedPackages)
	if err != nil {
		return nil, nil, err
	}

	// Build the list of installed package nodes.
	for _, p := range installedPackages {
		if p.Node != "" {
			installedNodes = append(installedNodes, p.Node)
		}
	}

	// Build the list of removed package nodes.
	for _, nv := range removedPackagesNV {
		node, _ := parentPackagesNVMapToNodes[nv]
		removedNodes = append(removedNodes, node)
	}

	return
}
