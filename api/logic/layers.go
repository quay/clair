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

package logic

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/julienschmidt/httprouter"

	"github.com/coreos/clair/database"
	cerrors "github.com/coreos/clair/utils/errors"
	httputils "github.com/coreos/clair/utils/http"
	"github.com/coreos/clair/utils/types"
	"github.com/coreos/clair/worker"
)

// POSTLayersParameters represents the expected parameters for POSTLayers.
type POSTLayersParameters struct {
	ID, Path, ParentID, ImageFormat string
}

// POSTLayers analyzes a layer and returns the engine version that has been used
// for the analysis.
func POSTLayers(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var parameters POSTLayersParameters
	if s, err := httputils.ParseHTTPBody(r, &parameters); err != nil {
		httputils.WriteHTTPError(w, s, err)
		return
	}

	// Process data.
	if err := worker.Process(parameters.ID, parameters.ParentID, parameters.Path, parameters.ImageFormat); err != nil {
		httputils.WriteHTTPError(w, 0, err)
		return
	}

	// Get engine version and return.
	httputils.WriteHTTP(w, http.StatusCreated, struct{ Version string }{Version: strconv.Itoa(worker.Version)})
}

// DELETELayers deletes the specified layer and any child layers that are
// dependent on the specified layer.
func DELETELayers(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
	err := database.DeleteLayer(p.ByName("id"))
	if err != nil {
		httputils.WriteHTTPError(w, 0, err)
		return
	}

	httputils.WriteHTTP(w, http.StatusNoContent, nil)
}

// GETLayersOS returns the operating system of a layer if it exists.
// It uses not only the specified layer but also its parent layers if necessary.
// An empty OS string is returned if no OS has been detected.
func GETLayersOS(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
	// Find layer.
	layer, err := database.FindOneLayerByID(p.ByName("id"), []string{database.FieldLayerParent, database.FieldLayerOS})
	if err != nil {
		httputils.WriteHTTPError(w, 0, err)
		return
	}

	// Get OS.
	os, err := layer.OperatingSystem()
	if err != nil {
		httputils.WriteHTTPError(w, 0, err)
		return
	}

	httputils.WriteHTTP(w, http.StatusOK, struct{ OS string }{OS: os})
}

// GETLayersParent returns the parent ID of a layer if it exists.
// An empty ID string is returned if the layer has no parent.
func GETLayersParent(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
	// Find layer
	layer, err := database.FindOneLayerByID(p.ByName("id"), []string{database.FieldLayerParent})
	if err != nil {
		httputils.WriteHTTPError(w, 0, err)
		return
	}

	// Get layer's parent.
	parent, err := layer.Parent([]string{database.FieldLayerID})
	if err != nil {
		httputils.WriteHTTPError(w, 0, err)
		return
	}

	ID := ""
	if parent != nil {
		ID = parent.ID
	}
	httputils.WriteHTTP(w, http.StatusOK, struct{ ID string }{ID: ID})
}

// GETLayersPackages returns the complete list of packages that a layer has
// if it exists.
func GETLayersPackages(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
	// Find layer
	layer, err := database.FindOneLayerByID(p.ByName("id"), []string{database.FieldLayerParent, database.FieldLayerPackages})
	if err != nil {
		httputils.WriteHTTPError(w, 0, err)
		return
	}

	// Find layer's packages.
	packagesNodes, err := layer.AllPackages()
	if err != nil {
		httputils.WriteHTTPError(w, 0, err)
		return
	}

	packages := []*database.Package{}
	if len(packagesNodes) > 0 {
		packages, err = database.FindAllPackagesByNodes(packagesNodes, []string{database.FieldPackageOS, database.FieldPackageName, database.FieldPackageVersion})
		if err != nil {
			httputils.WriteHTTPError(w, 0, err)
			return
		}
	}

	httputils.WriteHTTP(w, http.StatusOK, struct{ Packages []*database.Package }{Packages: packages})
}

// GETLayersPackagesDiff returns the list of packages that a layer installs and
// removes if it exists.
func GETLayersPackagesDiff(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
	// Find layer.
	layer, err := database.FindOneLayerByID(p.ByName("id"), []string{database.FieldLayerPackages})
	if err != nil {
		httputils.WriteHTTPError(w, 0, err)
		return
	}

	// Find layer's packages.
	installedPackages, removedPackages := make([]*database.Package, 0), make([]*database.Package, 0)
	if len(layer.InstalledPackagesNodes) > 0 {
		installedPackages, err = database.FindAllPackagesByNodes(layer.InstalledPackagesNodes, []string{database.FieldPackageOS, database.FieldPackageName, database.FieldPackageVersion})
		if err != nil {
			httputils.WriteHTTPError(w, 0, err)
			return
		}
	}
	if len(layer.RemovedPackagesNodes) > 0 {
		removedPackages, err = database.FindAllPackagesByNodes(layer.RemovedPackagesNodes, []string{database.FieldPackageOS, database.FieldPackageName, database.FieldPackageVersion})
		if err != nil {
			httputils.WriteHTTPError(w, 0, err)
			return
		}
	}

	httputils.WriteHTTP(w, http.StatusOK, struct{ InstalledPackages, RemovedPackages []*database.Package }{InstalledPackages: installedPackages, RemovedPackages: removedPackages})
}

// GETLayersVulnerabilities returns the complete list of vulnerabilities that
// a layer has if it exists.
func GETLayersVulnerabilities(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
	// Get minumum priority parameter.
	minimumPriority := types.Priority(r.URL.Query().Get("minimumPriority"))
	if minimumPriority == "" {
		minimumPriority = "High" // Set default priority to High
	} else if !minimumPriority.IsValid() {
		httputils.WriteHTTPError(w, 0, cerrors.NewBadRequestError("invalid priority"))
		return
	}

	// Find layer
	layer, err := database.FindOneLayerByID(p.ByName("id"), []string{database.FieldLayerParent, database.FieldLayerPackages})
	if err != nil {
		httputils.WriteHTTPError(w, 0, err)
		return
	}

	// Find layer's packages.
	packagesNodes, err := layer.AllPackages()
	if err != nil {
		httputils.WriteHTTPError(w, 0, err)
		return
	}

	// Find vulnerabilities.
	vulnerabilities, err := getVulnerabilitiesFromLayerPackagesNodes(packagesNodes, minimumPriority, []string{database.FieldVulnerabilityID, database.FieldVulnerabilityLink, database.FieldVulnerabilityPriority, database.FieldVulnerabilityDescription, database.FieldVulnerabilityCausedByPackage})
	if err != nil {
		httputils.WriteHTTPError(w, 0, err)
		return
	}

	httputils.WriteHTTP(w, http.StatusOK, struct{ Vulnerabilities []*database.Vulnerability }{Vulnerabilities: vulnerabilities})
}

// GETLayersVulnerabilitiesDiff returns the list of vulnerabilities that a layer
// adds and removes if it exists.
func GETLayersVulnerabilitiesDiff(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
	// Get minumum priority parameter.
	minimumPriority := types.Priority(r.URL.Query().Get("minimumPriority"))
	if minimumPriority == "" {
		minimumPriority = "High" // Set default priority to High
	} else if !minimumPriority.IsValid() {
		httputils.WriteHTTPError(w, 0, cerrors.NewBadRequestError("invalid priority"))
		return
	}

	// Find layer.
	layer, err := database.FindOneLayerByID(p.ByName("id"), []string{database.FieldLayerPackages})
	if err != nil {
		httputils.WriteHTTPError(w, 0, err)
		return
	}

	// Selected fields for vulnerabilities.
	selectedFields := []string{database.FieldVulnerabilityID, database.FieldVulnerabilityLink, database.FieldVulnerabilityPriority, database.FieldVulnerabilityDescription, database.FieldVulnerabilityCausedByPackage}

	// Find vulnerabilities for installed packages.
	addedVulnerabilities, err := getVulnerabilitiesFromLayerPackagesNodes(layer.InstalledPackagesNodes, minimumPriority, selectedFields)
	if err != nil {
		httputils.WriteHTTPError(w, 0, err)
		return
	}

	// Find vulnerabilities for removed packages.
	removedVulnerabilities, err := getVulnerabilitiesFromLayerPackagesNodes(layer.RemovedPackagesNodes, minimumPriority, selectedFields)
	if err != nil {
		httputils.WriteHTTPError(w, 0, err)
		return
	}

	// Remove vulnerabilities which appears both in added and removed lists (eg. case of updated packages but still vulnerable).
	for ia, a := range addedVulnerabilities {
		for ir, r := range removedVulnerabilities {
			if a.ID == r.ID {
				addedVulnerabilities = append(addedVulnerabilities[:ia], addedVulnerabilities[ia+1:]...)
				removedVulnerabilities = append(removedVulnerabilities[:ir], removedVulnerabilities[ir+1:]...)
			}
		}
	}

	httputils.WriteHTTP(w, http.StatusOK, struct{ Adds, Removes []*database.Vulnerability }{Adds: addedVulnerabilities, Removes: removedVulnerabilities})
}

// POSTBatchLayersVulnerabilitiesParameters represents the expected parameters
// for POSTBatchLayersVulnerabilities.
type POSTBatchLayersVulnerabilitiesParameters struct {
	LayersIDs []string
}

// POSTBatchLayersVulnerabilities returns the complete list of vulnerabilities
// that the provided layers have, if they all exist.
func POSTBatchLayersVulnerabilities(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
	// Parse body
	var parameters POSTBatchLayersVulnerabilitiesParameters
	if s, err := httputils.ParseHTTPBody(r, &parameters); err != nil {
		httputils.WriteHTTPError(w, s, err)
		return
	}
	if len(parameters.LayersIDs) == 0 {
		httputils.WriteHTTPError(w, http.StatusBadRequest, errors.New("at least one LayerID query parameter must be provided"))
		return
	}

	// Get minumum priority parameter.
	minimumPriority := types.Priority(r.URL.Query().Get("minimumPriority"))
	if minimumPriority == "" {
		minimumPriority = "High" // Set default priority to High
	} else if !minimumPriority.IsValid() {
		httputils.WriteHTTPError(w, 0, cerrors.NewBadRequestError("invalid priority"))
		return
	}

	response := make(map[string]interface{})
	// For each LayerID parameter
	for _, layerID := range parameters.LayersIDs {
		// Find layer
		layer, err := database.FindOneLayerByID(layerID, []string{database.FieldLayerParent, database.FieldLayerPackages})
		if err != nil {
			httputils.WriteHTTPError(w, 0, err)
			return
		}

		// Find layer's packages.
		packagesNodes, err := layer.AllPackages()
		if err != nil {
			httputils.WriteHTTPError(w, 0, err)
			return
		}

		// Find vulnerabilities.
		vulnerabilities, err := getVulnerabilitiesFromLayerPackagesNodes(packagesNodes, minimumPriority, []string{database.FieldVulnerabilityID, database.FieldVulnerabilityLink, database.FieldVulnerabilityPriority, database.FieldVulnerabilityDescription, database.FieldVulnerabilityCausedByPackage})
		if err != nil {
			httputils.WriteHTTPError(w, 0, err)
			return
		}

		response[layerID] = struct{ Vulnerabilities []*database.Vulnerability }{Vulnerabilities: vulnerabilities}
	}

	httputils.WriteHTTP(w, http.StatusOK, response)
}

// getSuccessorsFromPackagesNodes returns the node list of packages that have
// versions following the versions of the provided packages.
func getSuccessorsFromPackagesNodes(packagesNodes []string) ([]string, error) {
	if len(packagesNodes) == 0 {
		return []string{}, nil
	}

	// Get packages.
	packages, err := database.FindAllPackagesByNodes(packagesNodes, []string{database.FieldPackageNextVersion})
	if err != nil {
		return []string{}, err
	}

	// Find all packages' successors.
	var packagesNextVersions []string
	for _, pkg := range packages {
		nextVersions, err := pkg.NextVersions([]string{})
		if err != nil {
			return []string{}, err
		}
		for _, version := range nextVersions {
			packagesNextVersions = append(packagesNextVersions, version.Node)
		}
	}

	return packagesNextVersions, nil
}

// getVulnerabilitiesFromLayerPackagesNodes returns the list of vulnerabilities
// affecting the provided package nodes, filtered by Priority.
func getVulnerabilitiesFromLayerPackagesNodes(packagesNodes []string, minimumPriority types.Priority, selectedFields []string) ([]*database.Vulnerability, error) {
	if len(packagesNodes) == 0 {
		return []*database.Vulnerability{}, nil
	}

	// Get successors of the packages.
	packagesNextVersions, err := getSuccessorsFromPackagesNodes(packagesNodes)
	if err != nil {
		return []*database.Vulnerability{}, err
	}
	if len(packagesNextVersions) == 0 {
		return []*database.Vulnerability{}, nil
	}

	// Find vulnerabilities fixed in these successors.
	vulnerabilities, err := database.FindAllVulnerabilitiesByFixedIn(packagesNextVersions, selectedFields)
	if err != nil {
		return []*database.Vulnerability{}, err
	}

	// Filter vulnerabilities depending on their priority and remove duplicates.
	filteredVulnerabilities := []*database.Vulnerability{}
	seen := map[string]struct{}{}
	for _, v := range vulnerabilities {
		if minimumPriority.Compare(v.Priority) <= 0 {
			if _, alreadySeen := seen[v.ID]; !alreadySeen {
				filteredVulnerabilities = append(filteredVulnerabilities, v)
				seen[v.ID] = struct{}{}
			}
		}
	}

	return filteredVulnerabilities, nil
}
