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
const (
	maxBodySize int64 = 1048576

	postLayerRoute           = "v1/postLayer"
	getLayerRoute            = "v1/getLayer"
	deleteLayerRoute         = "v1/deleteLayer"
	getNamespacesRoute       = "v1/getNamespaces"
	postVulnerabilityRoute   = "v1/postVulnerability"
	getVulnerabilityRoute    = "v1/getVulnerability"
	putVulnerabilityRoute    = "v1/putVulnerability"
	deleteVulnerabilityRoute = "v1/deleteVulnerability"
	getFixesRoute            = "v1/getFixes"
	putFixRoute              = "v1/putFix"
	deleteFixRoute           = "v1/deleteFix"
	getNotificationRoute     = "v1/getNotification"
	deleteNotificationRoute  = "v1/deleteNotification"
	getMetricsRoute          = "v1/getMetrics"
)

func decodeJSON(r *http.Request, v interface{}) error {
	defer r.Body.Close()
	return json.NewDecoder(io.LimitReader(r.Body, maxBodySize)).Decode(v)
}

func writeResponse(w http.ResponseWriter, status int, resp interface{}) {
	header := w.Header()
	header.Set("Content-Type", "application/json;charset=utf-8")
	header.Set("Server", "clair")
	w.WriteHeader(status)
	err := json.NewEncoder(w).Encode(resp)
	if err != nil {
		panic("v1: failed to marshal response: " + err.Error())
	}
}

func postLayer(w http.ResponseWriter, r *http.Request, p httprouter.Params, ctx *context.RouteContext) (string, int) {
	request := LayerEnvelope{}
	err := decodeJSON(r, &request)
	if err != nil {
		writeResponse(w, http.StatusBadRequest, LayerEnvelope{Error: &Error{err.Error()}})
		return postLayerRoute, http.StatusBadRequest
	}

	if request.Layer == nil {
		writeResponse(w, http.StatusBadRequest, LayerEnvelope{Error: &Error{"failed to provide layer"}})
		return postLayerRoute, http.StatusBadRequest
	}

	err = worker.Process(ctx.Store, request.Layer.Name, request.Layer.ParentName, request.Layer.Path, request.Layer.Format)
	if err != nil {
		if _, ok := err.(*cerrors.ErrBadRequest); ok {
			writeResponse(w, http.StatusBadRequest, LayerEnvelope{Error: &Error{err.Error()}})
			return postLayerRoute, http.StatusBadRequest
		}
		writeResponse(w, http.StatusInternalServerError, LayerEnvelope{Error: &Error{err.Error()}})
		return postLayerRoute, http.StatusInternalServerError
	}

	w.WriteHeader(http.StatusCreated)
	return postLayerRoute, http.StatusCreated
}

func getLayer(w http.ResponseWriter, r *http.Request, p httprouter.Params, ctx *context.RouteContext) (string, int) {
	_, withFeatures := r.URL.Query()["features"]
	_, withVulnerabilities := r.URL.Query()["vulnerabilities"]

	dbLayer, err := ctx.Store.FindLayer(p.ByName("layerName"), withFeatures, withVulnerabilities)
	if err == cerrors.ErrNotFound {
		writeResponse(w, http.StatusNotFound, LayerEnvelope{Error: &Error{err.Error()}})
		return getLayerRoute, http.StatusNotFound
	} else if err != nil {
		writeResponse(w, http.StatusInternalServerError, LayerEnvelope{Error: &Error{err.Error()}})
		return getLayerRoute, http.StatusInternalServerError
	}

	layer := LayerFromDatabaseModel(dbLayer, withFeatures, withVulnerabilities)

	writeResponse(w, http.StatusOK, LayerEnvelope{Layer: &layer})
	return getLayerRoute, http.StatusOK
}

func deleteLayer(w http.ResponseWriter, r *http.Request, p httprouter.Params, ctx *context.RouteContext) (string, int) {
	err := ctx.Store.DeleteLayer(p.ByName("layerName"))
	if err == cerrors.ErrNotFound {
		writeResponse(w, http.StatusNotFound, LayerEnvelope{Error: &Error{err.Error()}})
		return deleteLayerRoute, http.StatusNotFound
	} else if err != nil {
		writeResponse(w, http.StatusInternalServerError, LayerEnvelope{Error: &Error{err.Error()}})
		return deleteLayerRoute, http.StatusInternalServerError
	}

	w.WriteHeader(http.StatusOK)
	return deleteLayerRoute, http.StatusOK
}

func getNamespaces(w http.ResponseWriter, r *http.Request, p httprouter.Params, ctx *context.RouteContext) (string, int) {
	dbNamespaces, err := ctx.Store.ListNamespaces()
	if err != nil {
		writeResponse(w, http.StatusInternalServerError, NamespaceEnvelope{Error: &Error{err.Error()}})
		return getNamespacesRoute, http.StatusInternalServerError
	}
	var namespaces []string
	for _, dbNamespace := range dbNamespaces {
		namespaces = append(namespaces, dbNamespace.Name)
	}

	writeResponse(w, http.StatusOK, NamespaceEnvelope{Namespaces: &namespaces})
	return getNamespacesRoute, http.StatusOK
}

func postVulnerability(w http.ResponseWriter, r *http.Request, p httprouter.Params, ctx *context.RouteContext) (string, int) {
	request := VulnerabilityEnvelope{}
	err := decodeJSON(r, &request)
	if err != nil {
		writeResponse(w, http.StatusBadRequest, VulnerabilityEnvelope{Error: &Error{err.Error()}})
		return postVulnerabilityRoute, http.StatusBadRequest
	}

	if request.Vulnerability == nil {
		writeResponse(w, http.StatusBadRequest, VulnerabilityEnvelope{Error: &Error{"failed to provide vulnerability"}})
		return postVulnerabilityRoute, http.StatusBadRequest
	}

	vuln, err := request.Vulnerability.DatabaseModel()
	if err != nil {
		writeResponse(w, http.StatusBadRequest, VulnerabilityEnvelope{Error: &Error{err.Error()}})
		return postVulnerabilityRoute, http.StatusBadRequest
	}

	err = ctx.Store.InsertVulnerabilities([]database.Vulnerability{vuln}, true)
	if err != nil {
		writeResponse(w, http.StatusInternalServerError, VulnerabilityEnvelope{Error: &Error{err.Error()}})
		return postVulnerabilityRoute, http.StatusInternalServerError
	}

	w.WriteHeader(http.StatusCreated)
	return postVulnerabilityRoute, http.StatusCreated
}

func getVulnerability(w http.ResponseWriter, r *http.Request, p httprouter.Params, ctx *context.RouteContext) (string, int) {
	_, withFixedIn := r.URL.Query()["fixedIn"]

	dbVuln, err := ctx.Store.FindVulnerability(p.ByName("namespaceName"), p.ByName("vulnerabilityName"))
	if err == cerrors.ErrNotFound {
		writeResponse(w, http.StatusNotFound, VulnerabilityEnvelope{Error: &Error{err.Error()}})
		return getVulnerabilityRoute, http.StatusNotFound
	} else if err != nil {
		writeResponse(w, http.StatusInternalServerError, VulnerabilityEnvelope{Error: &Error{err.Error()}})
		return getVulnerabilityRoute, http.StatusInternalServerError
	}

	vuln := VulnerabilityFromDatabaseModel(dbVuln, withFixedIn)

	writeResponse(w, http.StatusOK, VulnerabilityEnvelope{Vulnerability: &vuln})
	return getVulnerabilityRoute, http.StatusOK
}

func putVulnerability(w http.ResponseWriter, r *http.Request, p httprouter.Params, ctx *context.RouteContext) (string, int) {
	request := VulnerabilityEnvelope{}
	err := decodeJSON(r, &request)
	if err != nil {
		writeResponse(w, http.StatusBadRequest, VulnerabilityEnvelope{Error: &Error{err.Error()}})
		return putVulnerabilityRoute, http.StatusBadRequest
	}

	if request.Vulnerability == nil {
		writeResponse(w, http.StatusBadRequest, VulnerabilityEnvelope{Error: &Error{"failed to provide vulnerability"}})
		return putVulnerabilityRoute, http.StatusBadRequest
	}

	if len(request.Vulnerability.FixedIn) != 0 {
		writeResponse(w, http.StatusBadRequest, VulnerabilityEnvelope{Error: &Error{"Vulnerability.FixedIn must be empty"}})
		return putVulnerabilityRoute, http.StatusBadRequest
	}

	vuln, err := request.Vulnerability.DatabaseModel()
	if err != nil {
		writeResponse(w, http.StatusBadRequest, VulnerabilityEnvelope{Error: &Error{err.Error()}})
		return putVulnerabilityRoute, http.StatusBadRequest
	}

	vuln.Namespace.Name = p.ByName("namespaceName")
	vuln.Name = p.ByName("vulnerabilityName")

	err = ctx.Store.InsertVulnerabilities([]database.Vulnerability{vuln}, true)
	if err != nil {
		writeResponse(w, http.StatusInternalServerError, VulnerabilityEnvelope{Error: &Error{err.Error()}})
		return putVulnerabilityRoute, http.StatusInternalServerError
	}

	w.WriteHeader(http.StatusOK)
	return putVulnerabilityRoute, http.StatusOK
}

func deleteVulnerability(w http.ResponseWriter, r *http.Request, p httprouter.Params, ctx *context.RouteContext) (string, int) {
	err := ctx.Store.DeleteVulnerability(p.ByName("namespaceName"), p.ByName("vulnerabilityName"))
	if err == cerrors.ErrNotFound {
		writeResponse(w, http.StatusNotFound, VulnerabilityEnvelope{Error: &Error{err.Error()}})
		return deleteVulnerabilityRoute, http.StatusNotFound
	} else if err != nil {
		writeResponse(w, http.StatusInternalServerError, VulnerabilityEnvelope{Error: &Error{err.Error()}})
		return deleteVulnerabilityRoute, http.StatusInternalServerError
	}

	w.WriteHeader(http.StatusOK)
	return deleteVulnerabilityRoute, http.StatusOK
}

func getFixes(w http.ResponseWriter, r *http.Request, p httprouter.Params, ctx *context.RouteContext) (string, int) {
	dbVuln, err := ctx.Store.FindVulnerability(p.ByName("namespaceName"), p.ByName("vulnerabilityName"))
	if err == cerrors.ErrNotFound {
		writeResponse(w, http.StatusNotFound, FeatureEnvelope{Error: &Error{err.Error()}})
		return getFixesRoute, http.StatusNotFound
	} else if err != nil {
		writeResponse(w, http.StatusInternalServerError, FeatureEnvelope{Error: &Error{err.Error()}})
		return getFixesRoute, http.StatusInternalServerError
	}

	vuln := VulnerabilityFromDatabaseModel(dbVuln, true)
	writeResponse(w, http.StatusOK, FeatureEnvelope{Features: &vuln.FixedIn})
	return getFixesRoute, http.StatusOK
}

func putFix(w http.ResponseWriter, r *http.Request, p httprouter.Params, ctx *context.RouteContext) (string, int) {
	request := FeatureEnvelope{}
	err := decodeJSON(r, &request)
	if err != nil {
		writeResponse(w, http.StatusBadRequest, FeatureEnvelope{Error: &Error{err.Error()}})
		return putFixRoute, http.StatusBadRequest
	}

	if request.Feature == nil {
		writeResponse(w, http.StatusBadRequest, FeatureEnvelope{Error: &Error{"failed to provide feature"}})
		return putFixRoute, http.StatusBadRequest
	}

	if request.Feature.Name != p.ByName("fixName") {
		writeResponse(w, http.StatusBadRequest, FeatureEnvelope{Error: &Error{"feature name in URL and JSON do not match"}})
		return putFixRoute, http.StatusBadRequest
	}

	dbFix, err := request.Feature.DatabaseModel()
	if err != nil {
		writeResponse(w, http.StatusBadRequest, FeatureEnvelope{Error: &Error{err.Error()}})
		return putFixRoute, http.StatusBadRequest
	}

	err = ctx.Store.InsertVulnerabilityFixes(p.ByName("vulnerabilityNamespace"), p.ByName("vulnerabilityName"), []database.FeatureVersion{dbFix})
	if err == cerrors.ErrNotFound {
		writeResponse(w, http.StatusNotFound, FeatureEnvelope{Error: &Error{err.Error()}})
		return putFixRoute, http.StatusNotFound
	} else if err != nil {
		writeResponse(w, http.StatusInternalServerError, FeatureEnvelope{Error: &Error{err.Error()}})
		return putFixRoute, http.StatusInternalServerError
	}

	w.WriteHeader(http.StatusCreated)
	return putFixRoute, http.StatusCreated
}

func deleteFix(w http.ResponseWriter, r *http.Request, p httprouter.Params, ctx *context.RouteContext) (string, int) {
	err := ctx.Store.DeleteVulnerabilityFix(p.ByName("vulnerabilityNamespace"), p.ByName("vulnerabilityName"), p.ByName("fixName"))
	if err == cerrors.ErrNotFound {
		writeResponse(w, http.StatusNotFound, FeatureEnvelope{Error: &Error{err.Error()}})
		return deleteFixRoute, http.StatusNotFound
	} else if err != nil {
		writeResponse(w, http.StatusInternalServerError, FeatureEnvelope{Error: &Error{err.Error()}})
		return deleteFixRoute, http.StatusInternalServerError
	}

	w.WriteHeader(http.StatusOK)
	return deleteFixRoute, http.StatusOK
}

func getNotification(w http.ResponseWriter, r *http.Request, p httprouter.Params, ctx *context.RouteContext) (string, int) {
	query := r.URL.Query()

	limitStrs, limitExists := query["limit"]
	if !limitExists {
		writeResponse(w, http.StatusBadRequest, NotificationEnvelope{Error: &Error{"must provide limit query parameter"}})
		return getNotificationRoute, http.StatusBadRequest
	}
	limit, err := strconv.Atoi(limitStrs[0])
	if err != nil {
		writeResponse(w, http.StatusBadRequest, NotificationEnvelope{Error: &Error{"invalid limit format: " + err.Error()}})
		return getNotificationRoute, http.StatusBadRequest
	}

	page := database.VulnerabilityNotificationFirstPage
	pageStrs, pageExists := query["page"]
	if pageExists {
		page, err = tokenToPageNumber(pageStrs[0], ctx.Config.PaginationKey)
		if err != nil {
			writeResponse(w, http.StatusBadRequest, NotificationEnvelope{Error: &Error{"invalid page format: " + err.Error()}})
			return getNotificationRoute, http.StatusBadRequest
		}
	}

	dbNotification, nextPage, err := ctx.Store.GetNotification(p.ByName("notificationName"), limit, page)
	if err == cerrors.ErrNotFound {
		writeResponse(w, http.StatusNotFound, NotificationEnvelope{Error: &Error{err.Error()}})
		return deleteNotificationRoute, http.StatusNotFound
	} else if err != nil {
		writeResponse(w, http.StatusInternalServerError, NotificationEnvelope{Error: &Error{err.Error()}})
		return getNotificationRoute, http.StatusInternalServerError
	}

	notification := NotificationFromDatabaseModel(dbNotification, limit, page, nextPage, ctx.Config.PaginationKey)

	writeResponse(w, http.StatusOK, NotificationEnvelope{Notification: &notification})
	return getNotificationRoute, http.StatusOK
}

func deleteNotification(w http.ResponseWriter, r *http.Request, p httprouter.Params, ctx *context.RouteContext) (string, int) {
	err := ctx.Store.DeleteNotification(p.ByName("notificationName"))
	if err == cerrors.ErrNotFound {
		writeResponse(w, http.StatusNotFound, NotificationEnvelope{Error: &Error{err.Error()}})
		return deleteNotificationRoute, http.StatusNotFound
	} else if err != nil {
		writeResponse(w, http.StatusInternalServerError, NotificationEnvelope{Error: &Error{err.Error()}})
		return deleteNotificationRoute, http.StatusInternalServerError
	}

	w.WriteHeader(http.StatusOK)
	return deleteNotificationRoute, http.StatusOK
}

func getMetrics(w http.ResponseWriter, r *http.Request, p httprouter.Params, ctx *context.RouteContext) (string, int) {
	prometheus.Handler().ServeHTTP(w, r)
	return getMetricsRoute, 0
}
