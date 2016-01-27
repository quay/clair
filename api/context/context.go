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

package context

import (
	"fmt"
	"net/http"

	"github.com/coreos/pkg/capnslog"
	"github.com/julienschmidt/httprouter"

	"github.com/coreos/clair/database"
)

var log = capnslog.NewPackageLogger("github.com/coreos/clair", "api")

type Handler func(http.ResponseWriter, *http.Request, httprouter.Params, *RouteContext) int

func HTTPHandler(handler Handler, ctx *RouteContext) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		status := handler(w, r, p, ctx)
		statusStr := fmt.Sprintf("%d", status)
		if status == 0 {
			statusStr = "???"
		}

		log.Infof("%s %s %s %s", statusStr, r.Method, r.RequestURI, r.RemoteAddr)
	}
}

type RouteContext struct {
	Store database.Datastore
}
