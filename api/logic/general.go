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

// Package logic implements all the available API methods.
// Every methods are documented in docs/API.md.
package logic

import (
	"net/http"
	"strconv"

	"github.com/coreos/quay-sec/api/jsonhttp"
	"github.com/coreos/quay-sec/health"
	"github.com/coreos/quay-sec/worker"
	"github.com/julienschmidt/httprouter"
)

// Version is an integer representing the API version.
const Version = 1

// GETVersions returns API and Engine versions.
func GETVersions(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	jsonhttp.Render(w, http.StatusOK, struct {
		APIVersion    string
		EngineVersion string
	}{
		APIVersion:    strconv.Itoa(Version),
		EngineVersion: strconv.Itoa(worker.Version),
	})
}

// GETHealth sums up the health of all the registered services.
func GETHealth(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	globalHealth, statuses := health.Healthcheck()

	httpStatus := http.StatusOK
	if !globalHealth {
		httpStatus = http.StatusServiceUnavailable
	}

	jsonhttp.Render(w, httpStatus, statuses)
	return
}
