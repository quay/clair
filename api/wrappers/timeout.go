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

package wrappers

import (
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/julienschmidt/httprouter"

	httputils "github.com/coreos/clair/utils/http"
)

// ErrHandlerTimeout is returned on ResponseWriter Write calls
// in handlers which have timed out.
var ErrHandlerTimeout = errors.New("http: Handler timeout")

type timeoutWriter struct {
	http.ResponseWriter

	mu          sync.Mutex
	timedOut    bool
	wroteHeader bool
}

func (tw *timeoutWriter) Header() http.Header {
	return tw.ResponseWriter.Header()
}

func (tw *timeoutWriter) Write(p []byte) (int, error) {
	tw.mu.Lock()
	defer tw.mu.Unlock()
	tw.wroteHeader = true // implicitly at least
	if tw.timedOut {
		return 0, ErrHandlerTimeout
	}
	return tw.ResponseWriter.Write(p)
}

func (tw *timeoutWriter) WriteHeader(status int) {
	tw.mu.Lock()
	defer tw.mu.Unlock()
	if tw.timedOut || tw.wroteHeader {
		return
	}
	tw.wroteHeader = true
	tw.ResponseWriter.WriteHeader(status)
}

// TimeOut wraps a http.HandlerFunc and ensure that a response is given under
// the specified duration.
//
// If the handler takes longer than the time limit, the wrapper responds with
// a Service Unavailable error, an error message and the handler response which
// may come later is ignored.
//
// After a timeout, any write the handler to its ResponseWriter will return
// ErrHandlerTimeout.
//
// If the duration is 0, the wrapper does nothing.
func TimeOut(d time.Duration, fn httprouter.Handle) httprouter.Handle {
	if d == 0 {
		return fn
	}

	return func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		done := make(chan bool)
		tw := &timeoutWriter{ResponseWriter: w}

		go func() {
			fn(tw, r, p)
			done <- true
		}()

		select {
		case <-done:
			return
		case <-time.After(d):
			tw.mu.Lock()
			defer tw.mu.Unlock()
			if !tw.wroteHeader {
				httputils.WriteHTTPError(tw.ResponseWriter, http.StatusServiceUnavailable, ErrHandlerTimeout)
			}
			tw.timedOut = true
		}
	}
}
