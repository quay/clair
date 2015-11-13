// Copyright 2015 quay-sec authors
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

	"github.com/coreos/quay-sec/api/jsonhttp"
	"github.com/coreos/quay-sec/database"
	cerrors "github.com/coreos/quay-sec/utils/errors"
	"github.com/julienschmidt/httprouter"
)

// GETVulnerabilities returns a vulnerability identified by an ID if it exists.
func GETVulnerabilities(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
	// Find vulnerability.
	vulnerability, err := database.FindOneVulnerability(p.ByName("id"), []string{database.FieldVulnerabilityID, database.FieldVulnerabilityLink, database.FieldVulnerabilityPriority, database.FieldVulnerabilityDescription, database.FieldVulnerabilityFixedIn})
	if err != nil {
		jsonhttp.RenderError(w, 0, err)
		return
	}

	abstractVulnerability, err := vulnerability.ToAbstractVulnerability()
	if err != nil {
		jsonhttp.RenderError(w, 0, err)
		return
	}

	jsonhttp.Render(w, http.StatusOK, abstractVulnerability)
}

// POSTVulnerabilities manually inserts a vulnerability into the database if it
// does not exist yet.
func POSTVulnerabilities(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
	var parameters *database.AbstractVulnerability
	if s, err := jsonhttp.ParseBody(r, &parameters); err != nil {
		jsonhttp.RenderError(w, s, err)
		return
	}

	// Ensure that the vulnerability does not exist.
	vulnerability, err := database.FindOneVulnerability(parameters.ID, []string{})
	if err != nil && err != cerrors.ErrNotFound {
		jsonhttp.RenderError(w, 0, err)
		return
	}
	if vulnerability != nil {
		jsonhttp.RenderError(w, 0, cerrors.NewBadRequestError("vulnerability already exists"))
		return
	}

	// Insert packages.
	packages := database.AbstractPackagesToPackages(parameters.AffectedPackages)
	err = database.InsertPackages(packages)
	if err != nil {
		jsonhttp.RenderError(w, 0, err)
		return
	}
	var pkgNodes []string
	for _, p := range packages {
		pkgNodes = append(pkgNodes, p.Node)
	}

	// Insert vulnerability.
	notifications, err := database.InsertVulnerabilities([]*database.Vulnerability{parameters.ToVulnerability(pkgNodes)})
	if err != nil {
		jsonhttp.RenderError(w, 0, err)
		return
	}

	// Insert notifications.
	err = database.InsertNotifications(notifications, database.GetDefaultNotificationWrapper())
	if err != nil {
		jsonhttp.RenderError(w, 0, err)
		return
	}

	jsonhttp.Render(w, http.StatusCreated, nil)
}

// PUTVulnerabilities updates a vulnerability if it exists.
func PUTVulnerabilities(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
	var parameters *database.AbstractVulnerability
	if s, err := jsonhttp.ParseBody(r, &parameters); err != nil {
		jsonhttp.RenderError(w, s, err)
		return
	}
	parameters.ID = p.ByName("id")

	// Ensure that the vulnerability exists.
	_, err := database.FindOneVulnerability(parameters.ID, []string{})
	if err != nil {
		jsonhttp.RenderError(w, 0, err)
		return
	}

	// Insert packages.
	packages := database.AbstractPackagesToPackages(parameters.AffectedPackages)
	err = database.InsertPackages(packages)
	if err != nil {
		jsonhttp.RenderError(w, 0, err)
		return
	}
	var pkgNodes []string
	for _, p := range packages {
		pkgNodes = append(pkgNodes, p.Node)
	}

	// Insert vulnerability.
	notifications, err := database.InsertVulnerabilities([]*database.Vulnerability{parameters.ToVulnerability(pkgNodes)})
	if err != nil {
		jsonhttp.RenderError(w, 0, err)
		return
	}

	// Insert notifications.
	err = database.InsertNotifications(notifications, database.GetDefaultNotificationWrapper())
	if err != nil {
		jsonhttp.RenderError(w, 0, err)
		return
	}

	jsonhttp.Render(w, http.StatusCreated, nil)
}

// DELVulnerabilities deletes a vulnerability if it exists.
func DELVulnerabilities(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
	err := database.DeleteVulnerability(p.ByName("id"))
	if err != nil {
		jsonhttp.RenderError(w, 0, err)
		return
	}

	jsonhttp.Render(w, http.StatusNoContent, nil)
}

// GETVulnerabilitiesIntroducingLayers returns the list of layers that
// introduces a given vulnerability, if it exists.
// To clarify, it does not return the list of every layers that have
// the vulnerability.
func GETVulnerabilitiesIntroducingLayers(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
	// Find vulnerability to verify that it exists.
	_, err := database.FindOneVulnerability(p.ByName("id"), []string{})
	if err != nil {
		jsonhttp.RenderError(w, 0, err)
		return
	}

	layers, err := database.FindAllLayersIntroducingVulnerability(p.ByName("id"), []string{database.FieldLayerID})
	if err != nil {
		jsonhttp.RenderError(w, 0, err)
		return
	}

	layersIDs := []string{}
	for _, l := range layers {
		layersIDs = append(layersIDs, l.ID)
	}

	jsonhttp.Render(w, http.StatusOK, struct{ IntroducingLayersIDs []string }{IntroducingLayersIDs: layersIDs})
}

// POSTVulnerabilitiesAffectedLayersParameters represents the expected
// parameters for POSTVulnerabilitiesAffectedLayers.
type POSTVulnerabilitiesAffectedLayersParameters struct {
	LayersIDs []string
}

// POSTVulnerabilitiesAffectedLayers returns whether the specified layers
// (by their IDs) are vulnerable to the given Vulnerability or not.
func POSTVulnerabilitiesAffectedLayers(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
	// Parse body.
	var parameters POSTBatchLayersVulnerabilitiesParameters
	if s, err := jsonhttp.ParseBody(r, &parameters); err != nil {
		jsonhttp.RenderError(w, s, err)
		return
	}
	if len(parameters.LayersIDs) == 0 {
		jsonhttp.RenderError(w, http.StatusBadRequest, errors.New("getting the entire list of affected layers is not supported yet: at least one LayerID query parameter must be provided"))
		return
	}

	// Find vulnerability.
	vulnerability, err := database.FindOneVulnerability(p.ByName("id"), []string{database.FieldVulnerabilityFixedIn})
	if err != nil {
		jsonhttp.RenderError(w, 0, err)
		return
	}

	// Save the fixed in nodes into a map for fast check.
	fixedInPackagesMap := make(map[string]struct{})
	for _, fixedInNode := range vulnerability.FixedInNodes {
		fixedInPackagesMap[fixedInNode] = struct{}{}
	}

	response := make(map[string]interface{})
	// For each LayerID parameter.
	for _, layerID := range parameters.LayersIDs {
		// Find layer
		layer, err := database.FindOneLayerByID(layerID, []string{database.FieldLayerParent, database.FieldLayerPackages, database.FieldLayerPackages})
		if err != nil {
			jsonhttp.RenderError(w, 0, err)
			return
		}

		// Find layer's packages.
		packagesNodes, err := layer.AllPackages()
		if err != nil {
			jsonhttp.RenderError(w, 0, err)
			return
		}

		// Get successors packages of layer' packages.
		successors, err := getSuccessorsFromPackagesNodes(packagesNodes)
		if err != nil {
			jsonhttp.RenderError(w, 0, err)
			return
		}

		// Determine if the layer is vulnerable by verifying if one of the successors
		// of its packages are fixed by the vulnerability.
		vulnerable := false
		for _, p := range successors {
			if _, fixed := fixedInPackagesMap[p]; fixed {
				vulnerable = true
				break
			}
		}

		response[layerID] = struct{ Vulnerable bool }{Vulnerable: vulnerable}
	}

	jsonhttp.Render(w, http.StatusOK, response)
}
