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
	"github.com/coreos/clair/worker"
)

// maxBodySize restricts client requests to 1MiB.
const maxBodySize int64 = 1048576

func decodeJSON(r *http.Request, v interface{}) error {
	defer r.Body.Close()
	return json.NewDecoder(io.LimitReader(r.Body, maxBodySize)).Decode(v)
}

func writeError(w io.Writer, err error, errType string) {
	err = json.NewEncoder(w).Encode(ErrorResponse{Error{err.Error(), errType}})
	if err != nil {
		panic("v1: failed to marshal error response: " + err.Error())
	}
}

func postLayer(w http.ResponseWriter, r *http.Request, p httprouter.Params, ctx *context.RouteContext) int {
	request := LayerRequest{}
	err := decodeJSON(r, &request)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		writeError(w, err, "BadRequest")
		return http.StatusBadRequest
	}

	err = worker.Process(ctx.Store, request.Layer.Name, request.Layer.ParentName, request.Layer.Path, request.Layer.Format)
	if err != nil {
		if _, ok := err.(*cerrors.ErrBadRequest); ok {
			w.WriteHeader(http.StatusBadRequest)
			writeError(w, err, "BadRequest")
		}
		w.WriteHeader(http.StatusInternalServerError)
		writeError(w, err, "InternalServerError")
	}

	w.WriteHeader(http.StatusCreated)
	return http.StatusCreated
}

func getLayer(w http.ResponseWriter, r *http.Request, p httprouter.Params, ctx *context.RouteContext) int {
	// ez
	return 0
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
