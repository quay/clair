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

package v1

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"

	"github.com/julienschmidt/httprouter"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/coreos/clair/api/context"
	"github.com/coreos/clair/database"
	cerrors "github.com/coreos/clair/utils/errors"
	"github.com/coreos/clair/worker"
)

// maxBodySize restricts client requests to 1MiB.
const maxBodySize int64 = 1048576

func decodeJSON(r *http.Request, v interface{}) error {
	defer r.Body.Close()
	return json.NewDecoder(io.LimitReader(r.Body, maxBodySize)).Decode(v)
}

func writeResponse(w io.Writer, resp interface{}) {
	err := json.NewEncoder(w).Encode(resp)
	if err != nil {
		panic("v1: failed to marshal response: " + err.Error())
	}
}

func writeHeader(w http.ResponseWriter, status int) int {
	w.WriteHeader(status)
	return status
}

func postLayer(w http.ResponseWriter, r *http.Request, p httprouter.Params, ctx *context.RouteContext) int {
	request := LayerEnvelope{}
	err := decodeJSON(r, &request)
	if err != nil {
		writeResponse(w, LayerEnvelope{Error: &Error{err.Error()}})
		return writeHeader(w, http.StatusBadRequest)
	}

	if request.Layer == nil {
		writeResponse(w, LayerEnvelope{Error: &Error{"failed to provide layer"}})
		return writeHeader(w, http.StatusBadRequest)
	}

	err = worker.Process(ctx.Store, request.Layer.Name, request.Layer.ParentName, request.Layer.Path, request.Layer.Format)
	if err != nil {
		if _, ok := err.(*cerrors.ErrBadRequest); ok {
			writeResponse(w, LayerEnvelope{Error: &Error{err.Error()}})
			return writeHeader(w, http.StatusBadRequest)
		}
		writeResponse(w, LayerEnvelope{Error: &Error{err.Error()}})
		return writeHeader(w, http.StatusInternalServerError)
	}

	return writeHeader(w, http.StatusCreated)
}

func getLayer(w http.ResponseWriter, r *http.Request, p httprouter.Params, ctx *context.RouteContext) int {
	_, withFeatures := r.URL.Query()["features"]
	_, withVulnerabilities := r.URL.Query()["vulnerabilities"]

	dbLayer, err := ctx.Store.FindLayer(p.ByName("layerName"), withFeatures, withVulnerabilities)
	if err == cerrors.ErrNotFound {
		writeResponse(w, LayerEnvelope{Error: &Error{err.Error()}})
		return writeHeader(w, http.StatusNotFound)
	} else if err != nil {
		writeResponse(w, LayerEnvelope{Error: &Error{err.Error()}})
		return writeHeader(w, http.StatusInternalServerError)
	}

	layer := LayerFromDatabaseModel(dbLayer, withFeatures, withVulnerabilities)

	writeResponse(w, LayerEnvelope{Layer: &layer})
	return writeHeader(w, http.StatusOK)
}

func deleteLayer(w http.ResponseWriter, r *http.Request, p httprouter.Params, ctx *context.RouteContext) int {
	err := ctx.Store.DeleteLayer(p.ByName("layerName"))
	if err == cerrors.ErrNotFound {
		writeResponse(w, LayerEnvelope{Error: &Error{err.Error()}})
		return writeHeader(w, http.StatusNotFound)
	} else if err != nil {
		writeResponse(w, LayerEnvelope{Error: &Error{err.Error()}})
		return writeHeader(w, http.StatusInternalServerError)
	}

	return writeHeader(w, http.StatusOK)
}

func getNamespaces(w http.ResponseWriter, r *http.Request, p httprouter.Params, ctx *context.RouteContext) int {
	dbNamespaces, err := ctx.Store.ListNamespaces()
	if err != nil {
		writeResponse(w, NamespaceEnvelope{Error: &Error{err.Error()}})
		return writeHeader(w, http.StatusInternalServerError)
	}
	var namespaces []string
	for _, dbNamespace := range dbNamespaces {
		namespaces = append(namespaces, dbNamespace.Name)
	}

	writeResponse(w, NamespaceEnvelope{Namespaces: &namespaces})
	return writeHeader(w, http.StatusOK)
}

func postVulnerability(w http.ResponseWriter, r *http.Request, p httprouter.Params, ctx *context.RouteContext) int {
	request := VulnerabilityEnvelope{}
	err := decodeJSON(r, &request)
	if err != nil {
		writeResponse(w, VulnerabilityEnvelope{Error: &Error{err.Error()}})
		return writeHeader(w, http.StatusBadRequest)
	}

	if request.Vulnerability == nil {
		writeResponse(w, VulnerabilityEnvelope{Error: &Error{"failed to provide vulnerability"}})
		return writeHeader(w, http.StatusBadRequest)
	}

	vuln, err := request.Vulnerability.DatabaseModel()
	if err != nil {
		writeResponse(w, VulnerabilityEnvelope{Error: &Error{err.Error()}})
		return writeHeader(w, http.StatusBadRequest)
	}

	err = ctx.Store.InsertVulnerabilities([]database.Vulnerability{vuln})
	if err != nil {
		writeResponse(w, VulnerabilityEnvelope{Error: &Error{err.Error()}})
		return writeHeader(w, http.StatusInternalServerError)
	}

	return writeHeader(w, http.StatusCreated)
}

func getVulnerability(w http.ResponseWriter, r *http.Request, p httprouter.Params, ctx *context.RouteContext) int {
	_, withFixedIn := r.URL.Query()["fixedIn"]

	dbVuln, err := ctx.Store.FindVulnerability(p.ByName("namespaceName"), p.ByName("vulnerabilityName"))
	if err == cerrors.ErrNotFound {
		writeResponse(w, VulnerabilityEnvelope{Error: &Error{err.Error()}})
		return writeHeader(w, http.StatusNotFound)
	} else if err != nil {
		writeResponse(w, VulnerabilityEnvelope{Error: &Error{err.Error()}})
		return writeHeader(w, http.StatusInternalServerError)
	}

	vuln := VulnerabilityFromDatabaseModel(dbVuln, withFixedIn)

	writeResponse(w, VulnerabilityEnvelope{Vulnerability: &vuln})
	return writeHeader(w, http.StatusOK)
}

func putVulnerability(w http.ResponseWriter, r *http.Request, p httprouter.Params, ctx *context.RouteContext) int {
	request := VulnerabilityEnvelope{}
	err := decodeJSON(r, &request)
	if err != nil {
		writeResponse(w, VulnerabilityEnvelope{Error: &Error{err.Error()}})
		return writeHeader(w, http.StatusBadRequest)
	}

	if request.Vulnerability == nil {
		writeResponse(w, VulnerabilityEnvelope{Error: &Error{"failed to provide vulnerability"}})
		return writeHeader(w, http.StatusBadRequest)
	}

	if len(request.Vulnerability.FixedIn) != 0 {
		writeResponse(w, VulnerabilityEnvelope{Error: &Error{"Vulnerability.FixedIn must be empty"}})
		return writeHeader(w, http.StatusBadRequest)
	}

	vuln, err := request.Vulnerability.DatabaseModel()
	if err != nil {
		writeResponse(w, VulnerabilityEnvelope{Error: &Error{err.Error()}})
		return writeHeader(w, http.StatusBadRequest)
	}

	err = ctx.Store.InsertVulnerabilities([]database.Vulnerability{vuln})
	if err != nil {
		writeResponse(w, VulnerabilityEnvelope{Error: &Error{err.Error()}})
		return writeHeader(w, http.StatusInternalServerError)
	}

	return writeHeader(w, http.StatusOK)
}

func deleteVulnerability(w http.ResponseWriter, r *http.Request, p httprouter.Params, ctx *context.RouteContext) int {
	err := ctx.Store.DeleteVulnerability(p.ByName("namespaceName"), p.ByName("vulnerabilityName"))
	if err == cerrors.ErrNotFound {
		writeResponse(w, VulnerabilityEnvelope{Error: &Error{err.Error()}})
		return writeHeader(w, http.StatusNotFound)
	} else if err != nil {
		writeResponse(w, VulnerabilityEnvelope{Error: &Error{err.Error()}})
		return writeHeader(w, http.StatusInternalServerError)
	}

	return writeHeader(w, http.StatusOK)
}

func postFix(w http.ResponseWriter, r *http.Request, p httprouter.Params, ctx *context.RouteContext) int {
	return 0
}
func getFixes(w http.ResponseWriter, r *http.Request, p httprouter.Params, ctx *context.RouteContext) int {
	return 0
}
func putFix(w http.ResponseWriter, r *http.Request, p httprouter.Params, ctx *context.RouteContext) int {
	return 0
}
func deleteFix(w http.ResponseWriter, r *http.Request, p httprouter.Params, ctx *context.RouteContext) int {
	return 0
}

func getNotification(w http.ResponseWriter, r *http.Request, p httprouter.Params, ctx *context.RouteContext) int {
	query := r.URL.Query()

	limitStrs, limitExists := query["limit"]
	if !limitExists {
		writeResponse(w, NotificationEnvelope{Error: &Error{"must provide limit query parameter"}})
		return writeHeader(w, http.StatusBadRequest)
	}
	limit, err := strconv.Atoi(limitStrs[0])
	if err != nil {
		writeResponse(w, NotificationEnvelope{Error: &Error{"invalid limit format: " + err.Error()}})
		return writeHeader(w, http.StatusBadRequest)
	}

	page := database.VulnerabilityNotificationFirstPage
	pageStrs, pageExists := query["page"]
	if pageExists {
		page, err = pageStringToDBPageNumber(pageStrs[0])
		if err != nil {
			writeResponse(w, NotificationEnvelope{Error: &Error{"invalid page format: " + err.Error()}})
			return writeHeader(w, http.StatusBadRequest)
		}
	}

	dbNotification, nextPage, err := ctx.Store.GetNotification(p.ByName("notificationName"), limit, page)
	if err != nil {
		writeResponse(w, NotificationEnvelope{Error: &Error{err.Error()}})
		return writeHeader(w, http.StatusInternalServerError)
	}

	notification := NotificationFromDatabaseModel(dbNotification, limit, page, nextPage)

	writeResponse(w, NotificationEnvelope{Notification: &notification})
	return writeHeader(w, http.StatusOK)
}

func deleteNotification(w http.ResponseWriter, r *http.Request, p httprouter.Params, ctx *context.RouteContext) int {
	// ez
	return 0
}

func getMetrics(w http.ResponseWriter, r *http.Request, p httprouter.Params, ctx *context.RouteContext) int {
	prometheus.Handler().ServeHTTP(w, r)
	return 0
}
