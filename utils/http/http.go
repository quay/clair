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

// Package http provides utility functions for HTTP servers and clients.
package http

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/coreos/clair/database"
	cerrors "github.com/coreos/clair/utils/errors"
	"github.com/coreos/clair/worker"
)

// MaxPostSize is the maximum number of bytes that ParseHTTPBody reads from an http.Request.Body.
const MaxBodySize int64 = 1048576

// WriteHTTP writes a JSON-encoded object to a http.ResponseWriter, as well as
// a HTTP status code.
func WriteHTTP(w http.ResponseWriter, httpStatus int, v interface{}) {
	w.WriteHeader(httpStatus)
	if v != nil {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		result, _ := json.Marshal(v)
		w.Write(result)
	}
}

// WriteHTTPError writes an error, wrapped in the Message field of a JSON-encoded
// object to a http.ResponseWriter, as well as a HTTP status code.
// If the status code is 0, handleError tries to guess the proper HTTP status
// code from the error type.
func WriteHTTPError(w http.ResponseWriter, httpStatus int, err error) {
	if httpStatus == 0 {
		httpStatus = http.StatusInternalServerError
		// Try to guess the http status code from the error type
		if _, isBadRequestError := err.(*cerrors.ErrBadRequest); isBadRequestError {
			httpStatus = http.StatusBadRequest
		} else {
			switch err {
			case cerrors.ErrNotFound:
				httpStatus = http.StatusNotFound
			case database.ErrTransaction, database.ErrBackendException:
				httpStatus = http.StatusServiceUnavailable
			case worker.ErrParentUnknown, worker.ErrUnsupported:
				httpStatus = http.StatusBadRequest
			}
		}
	}

	WriteHTTP(w, httpStatus, struct{ Message string }{Message: err.Error()})
}

// ParseHTTPBody reads a JSON-encoded body from a http.Request and unmarshals it
// into the provided object.
func ParseHTTPBody(r *http.Request, v interface{}) (int, error) {
	defer r.Body.Close()
	err := json.NewDecoder(io.LimitReader(r.Body, MaxBodySize)).Decode(v)
	if err != nil {
		return http.StatusUnsupportedMediaType, err
	}
	return 0, nil
}
