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

// Package wrappers contains httprouter.Handle wrappers that are used in the API.
package wrappers

import (
	"net/http"
	"time"

	"github.com/coreos/pkg/capnslog"
	"github.com/julienschmidt/httprouter"
)

var log = capnslog.NewPackageLogger("github.com/coreos/clair", "api")

type logWriter struct {
	http.ResponseWriter
	status int
	size   int
}

func (lw *logWriter) Header() http.Header {
	return lw.ResponseWriter.Header()
}

func (lw *logWriter) Write(b []byte) (int, error) {
	if !lw.Written() {
		lw.WriteHeader(http.StatusOK)
	}
	size, err := lw.ResponseWriter.Write(b)
	lw.size += size
	return size, err
}

func (lw *logWriter) WriteHeader(s int) {
	lw.status = s
	lw.ResponseWriter.WriteHeader(s)
}

func (lw *logWriter) Size() int {
	return lw.size
}

func (lw *logWriter) Written() bool {
	return lw.status != 0
}

func (lw *logWriter) Status() int {
	return lw.status
}

// Log wraps a http.HandlerFunc and logs the API call
func Log(fn httprouter.Handle) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		lw := &logWriter{ResponseWriter: w}
		start := time.Now()
		fn(lw, r, p)
		log.Infof("%d %s %s (%s)", lw.Status(), r.Method, r.RequestURI, time.Since(start))
	}
}
