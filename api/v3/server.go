// Copyright 2018 clair authors
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

package v3

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"

	pb "github.com/coreos/clair/api/v3/clairpb"
	"github.com/coreos/clair/database"
	"github.com/coreos/clair/pkg/grpcutil"
)

var (
	promResponseDurationMilliseconds = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "clair_v3_api_response_duration_milliseconds",
		Help:    "The duration of time it takes to receive and write a response to an V2 API request",
		Buckets: prometheus.ExponentialBuckets(9.375, 2, 10),
	}, []string{"route", "code"})
)

func init() {
	prometheus.MustRegister(promResponseDurationMilliseconds)
}

func prometheusHandler(h http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/", h)
	mux.Handle("/metrics", prometheus.Handler())
	return mux
}

type httpStatusWriter struct {
	http.ResponseWriter

	StatusCode int
}

func (w *httpStatusWriter) WriteHeader(code int) {
	w.StatusCode = code
	w.ResponseWriter.WriteHeader(code)
}

func loggingHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		lrw := &httpStatusWriter{ResponseWriter: w, StatusCode: http.StatusOK}

		h.ServeHTTP(lrw, r)

		log.WithFields(log.Fields{
			"remote addr":       r.RemoteAddr,
			"method":            r.Method,
			"request uri":       r.RequestURI,
			"status":            strconv.Itoa(lrw.StatusCode),
			"elapsed time (ms)": float64(time.Since(start).Nanoseconds()) * 1e-6,
		}).Info("handled HTTP request")
	})
}

// ListenAndServe serves the Clair v3 API over gRPC and the gRPC Gateway.
func ListenAndServe(addr, certFile, keyFile, caPath string, store database.Datastore) error {
	srv := grpcutil.MuxedGRPCServer{
		Addr: addr,
		ServicesFunc: func(gsrv *grpc.Server) {
			pb.RegisterAncestryServiceServer(gsrv, &AncestryServer{Store: store})
			pb.RegisterNotificationServiceServer(gsrv, &NotificationServer{Store: store})
			pb.RegisterStatusServiceServer(gsrv, &StatusServer{Store: store})
		},
		ServiceHandlerFuncs: []grpcutil.RegisterServiceHandlerFunc{
			pb.RegisterAncestryServiceHandler,
			pb.RegisterNotificationServiceHandler,
			pb.RegisterStatusServiceHandler,
		},
	}

	middleware := func(h http.Handler) http.Handler {
		return prometheusHandler(loggingHandler(h))
	}

	var err error
	if caPath == "" {
		err = srv.ListenAndServe(middleware)
	} else {
		err = srv.ListenAndServeTLS(certFile, keyFile, caPath, middleware)
	}
	return err
}
