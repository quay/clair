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

package api

import (
	"net/http"

	"github.com/julienschmidt/httprouter"

	"github.com/coreos/clair/database"
)

// router is an HTTP router that forwards requests to the appropriate sub-router
// depending on the API version specified in the request URI.
type router map[string]*httprouter.Router

func newHealthHandler(store database.Datastore) http.Handler {
	router := httprouter.New()
	router.GET("/health", healthHandler(store))
	return router
}

func healthHandler(store database.Datastore) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		header := w.Header()
		header.Set("Server", "clair")

		status := http.StatusInternalServerError
		if store.Ping() {
			status = http.StatusOK
		}

		w.WriteHeader(status)
	}
}
