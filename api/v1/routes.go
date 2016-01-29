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

	"github.com/julienschmidt/httprouter"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/coreos/clair/api/context"
	cerrors "github.com/coreos/clair/utils/errors"
	"github.com/coreos/clair/utils/types"
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
		writeResponse(w, LayerEnvelope{Error: Error{err.Error()}})
		return writeHeader(w, http.StatusBadRequest)
	}

	err = worker.Process(ctx.Store, request.Layer.Name, request.Layer.ParentName, request.Layer.Path, request.Layer.Format)
	if err != nil {
		if _, ok := err.(*cerrors.ErrBadRequest); ok {
			writeResponse(w, LayerEnvelope{Error: Error{err.Error()}})
			return writeHeader(w, http.StatusBadRequest)
		}
		writeResponse(w, LayerEnvelope{Error: Error{err.Error()}})
		return writeHeader(w, http.StatusInternalServerError)
	}

	return writeHeader(w, http.StatusCreated)
}

func getLayer(w http.ResponseWriter, r *http.Request, p httprouter.Params, ctx *context.RouteContext) int {
	_, withFeatures := r.URL.Query()["features"]
	_, withVulnerabilities := r.URL.Query()["vulnerabilities"]

	dbLayer, err := ctx.Store.FindLayer(p.ByName("layerName"), withFeatures, withVulnerabilities)
	if err == cerrors.ErrNotFound {
		writeResponse(w, LayerEnvelope{Error: Error{err.Error()}})
		return writeHeader(w, http.StatusNotFound)
	} else if err != nil {
		writeResponse(w, LayerEnvelope{Error: Error{err.Error()}})
		return writeHeader(w, http.StatusInternalServerError)
	}

	layer := Layer{
		Name:             dbLayer.Name,
		IndexedByVersion: dbLayer.EngineVersion,
	}

	if dbLayer.Parent != nil {
		layer.ParentName = dbLayer.Parent.Name
	}

	if dbLayer.Namespace != nil {
		layer.NamespaceName = dbLayer.Namespace.Name
	}

	if withFeatures || withVulnerabilities && dbLayer.Features != nil {
		for _, dbFeatureVersion := range dbLayer.Features {
			feature := Feature{
				Name:      dbFeatureVersion.Feature.Name,
				Namespace: dbFeatureVersion.Feature.Namespace.Name,
				Version:   dbFeatureVersion.Version.String(),
			}

			for _, dbVuln := range dbFeatureVersion.AffectedBy {
				vuln := Vulnerability{
					Name:          dbVuln.Name,
					NamespaceName: dbVuln.Namespace.Name,
					Description:   dbVuln.Description,
					Severity:      string(dbVuln.Severity),
				}

				if dbVuln.FixedBy != types.MaxVersion {
					vuln.FixedBy = dbVuln.FixedBy.String()
				}
				feature.Vulnerabilities = append(feature.Vulnerabilities, vuln)
			}
			layer.Features = append(layer.Features, feature)
		}
	}

	// add envelope
	writeResponse(w, LayerEnvelope{Layer: layer})
	return writeHeader(w, http.StatusOK)
}

func deleteLayer(w http.ResponseWriter, r *http.Request, p httprouter.Params, ctx *context.RouteContext) int {
	// ez
	return 0
}

func getNamespaces(w http.ResponseWriter, r *http.Request, p httprouter.Params, ctx *context.RouteContext) int {
	return 0
}

func postVulnerability(w http.ResponseWriter, r *http.Request, p httprouter.Params, ctx *context.RouteContext) int {
	// ez
	return 0
}
func getVulnerability(w http.ResponseWriter, r *http.Request, p httprouter.Params, ctx *context.RouteContext) int {
	// ez
	return 0
}
func patchVulnerability(w http.ResponseWriter, r *http.Request, p httprouter.Params, ctx *context.RouteContext) int {
	// ez
	return 0
}
func deleteVulnerability(w http.ResponseWriter, r *http.Request, p httprouter.Params, ctx *context.RouteContext) int {
	// ez
	return 0
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
	// ez
	return 0
}
func deleteNotification(w http.ResponseWriter, r *http.Request, p httprouter.Params, ctx *context.RouteContext) int {
	// ez
	return 0
}

func getMetrics(w http.ResponseWriter, r *http.Request, p httprouter.Params, ctx *context.RouteContext) int {
	prometheus.Handler().ServeHTTP(w, r)
	return 0
}
