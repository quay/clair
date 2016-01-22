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

package api

import (
	"net/http"
	"strconv"

	"github.com/julienschmidt/httprouter"

	"github.com/coreos/clair/database"
	httputils "github.com/coreos/clair/utils/http"
	"github.com/coreos/clair/worker"
)

// Version is an integer representing the API version.
const Version = 1

// POSTLayersParameters represents the expected parameters for POSTLayers.
type POSTLayersParameters struct {
	Name, Path, ParentName string
}

// GETVersions returns API and Engine versions.
func GETVersions(w http.ResponseWriter, r *http.Request, _ httprouter.Params, _ *Env) {
	httputils.WriteHTTP(w, http.StatusOK, struct {
		APIVersion    string
		EngineVersion string
	}{
		APIVersion:    strconv.Itoa(Version),
		EngineVersion: strconv.Itoa(worker.Version),
	})
}

// GETHealth sums up the health of all the registered services.
func GETHealth(w http.ResponseWriter, r *http.Request, _ httprouter.Params, e *Env) {
	// globalHealth, statuses := health.Healthcheck(e.Datastore)
	//
	// httpStatus := http.StatusOK
	// if !globalHealth {
	// 	httpStatus = http.StatusServiceUnavailable
	// }
	//
	// httputils.WriteHTTP(w, httpStatus, statuses)
	return
}

// POSTLayers analyzes a layer and returns the engine version that has been used
// for the analysis.
func POSTLayers(w http.ResponseWriter, r *http.Request, _ httprouter.Params, e *Env) {
	var parameters POSTLayersParameters
	if s, err := httputils.ParseHTTPBody(r, &parameters); err != nil {
		httputils.WriteHTTPError(w, s, err)
		return
	}

	// Process data.
	if err := worker.Process(e.Datastore, parameters.Name, parameters.ParentName, parameters.Path); err != nil {
		httputils.WriteHTTPError(w, 0, err)
		return
	}

	// Get engine version and return.
	httputils.WriteHTTP(w, http.StatusCreated, struct{ Version string }{Version: strconv.Itoa(worker.Version)})
}

// DELETELayers deletes the specified layer and any child layers that are
// dependent on the specified layer.
func DELETELayers(w http.ResponseWriter, r *http.Request, p httprouter.Params, e *Env) {
	if err := e.Datastore.DeleteLayer(p.ByName("name")); err != nil {
		httputils.WriteHTTPError(w, 0, err)
		return
	}
	httputils.WriteHTTP(w, http.StatusNoContent, nil)
}

// GETLayers returns informations about an existing layer, optionally with its features
// and vulnerabilities.
func GETLayers(w http.ResponseWriter, r *http.Request, p httprouter.Params, e *Env) {
	_, withFeatures := r.URL.Query()["withFeatures"]
	_, withVulnerabilities := r.URL.Query()["withVulnerabilities"]

	layer, err := e.Datastore.FindLayer(p.ByName("name"), withFeatures, withVulnerabilities)
	if err != nil {
		httputils.WriteHTTPError(w, 0, err)
		return
	}

	httputils.WriteHTTP(w, http.StatusOK, struct{ Layer database.Layer }{Layer: layer})
}
