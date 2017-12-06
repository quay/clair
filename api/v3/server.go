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

package v3

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/cockroachdb/cmux"
	"github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	pb "github.com/coreos/clair/api/v3/clairpb"
	"github.com/coreos/clair/database"
)

// handleShutdown handles the server shut down error.
func handleShutdown(err error) {
	if err != nil {
		if opErr, ok := err.(*net.OpError); !ok || (ok && opErr.Op != "accept") {
			log.Fatal(err)
		}
	}
}

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

func newGrpcServer(store database.Datastore, tlsConfig *tls.Config) *grpc.Server {
	grpcOpts := []grpc.ServerOption{
		grpc.UnaryInterceptor(grpc_prometheus.UnaryServerInterceptor),
		grpc.StreamInterceptor(grpc_prometheus.StreamServerInterceptor),
	}

	if tlsConfig != nil {
		grpcOpts = append(grpcOpts, grpc.Creds(credentials.NewTLS(tlsConfig)))
	}

	grpcServer := grpc.NewServer(grpcOpts...)
	pb.RegisterAncestryServiceServer(grpcServer, &AncestryServer{Store: store})
	pb.RegisterNotificationServiceServer(grpcServer, &NotificationServer{Store: store})
	return grpcServer
}

type httpStatusWritter struct {
	http.ResponseWriter

	StatusCode int
}

func (w *httpStatusWritter) WriteHeader(code int) {
	w.StatusCode = code
	w.ResponseWriter.WriteHeader(code)
}

// logHandler adds request logging to an http handler.
func logHandler(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		lrw := &httpStatusWritter{ResponseWriter: w, StatusCode: http.StatusOK}

		handler.ServeHTTP(lrw, r)

		statusStr := strconv.Itoa(lrw.StatusCode)
		if lrw.StatusCode == 0 {
			statusStr = "???"
		}

		log.WithFields(log.Fields{
			"remote addr":       r.RemoteAddr,
			"method":            r.Method,
			"request uri":       r.RequestURI,
			"status":            statusStr,
			"elapsed time (ms)": float64(time.Since(start).Nanoseconds()) * 1e-6,
		}).Info("Handled HTTP request")
	})
}

func newGrpcGatewayServer(ctx context.Context, listenerAddr string, tlsConfig *tls.Config) http.Handler {
	var (
		gwTLSConfig *tls.Config
		gwOpts      []grpc.DialOption
	)

	if tlsConfig != nil {
		gwTLSConfig = tlsConfig.Clone()
		gwTLSConfig.InsecureSkipVerify = true
		gwOpts = append(gwOpts, grpc.WithTransportCredentials(credentials.NewTLS(gwTLSConfig)))
	} else {
		gwOpts = append(gwOpts, grpc.WithInsecure())
	}

	// changes json serializer to include empty fields with default values
	jsonOpt := runtime.WithMarshalerOption(runtime.MIMEWildcard, &runtime.JSONPb{EmitDefaults: true})
	gwmux := runtime.NewServeMux(jsonOpt)

	conn, err := grpc.DialContext(ctx, listenerAddr, gwOpts...)
	if err != nil {
		log.WithError(err).Fatal("could not initialize grpc gateway connection")
	}

	err = pb.RegisterAncestryServiceHandler(ctx, gwmux, conn)
	if err != nil {
		log.WithError(err).Fatal("could not initialize ancestry grpc gateway")
	}

	err = pb.RegisterNotificationServiceHandler(ctx, gwmux, conn)
	if err != nil {
		log.WithError(err).Fatal("could not initialize notification grpc gateway")
	}

	return logHandler(gwmux)
}

func servePrometheus(mux *http.ServeMux) {
	mux.Handle("/metrics", prometheus.Handler())
}

// Run initializes grpc and grpc gateway api services on the same address
func Run(Addr string, tlsConfig *tls.Config, CertFile, KeyFile string, store database.Datastore) {
	l, err := net.Listen("tcp", Addr)
	if err != nil {
		log.WithError(err).Fatalf("could not listen to address" + Addr)
	}
	log.WithField("addr", l.Addr().String()).Info("starting grpc server")

	var (
		apiHandler  http.Handler
		apiListener net.Listener
		srv         *http.Server
		ctx         = context.Background()
		httpMux     = http.NewServeMux()
		tcpMux      = cmux.New(l)
	)

	if tlsConfig != nil {
		cert, err := tls.LoadX509KeyPair(CertFile, KeyFile)
		if err != nil {
			log.WithError(err).Fatal("Failed to load certificate files")
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
		tlsConfig.NextProtos = []string{"h2"}

		apiListener = tls.NewListener(tcpMux.Match(cmux.Any()), tlsConfig)
		go func() { handleShutdown(tcpMux.Serve()) }()

		grpcServer := newGrpcServer(store, tlsConfig)
		gwmux := newGrpcGatewayServer(ctx, apiListener.Addr().String(), tlsConfig)

		httpMux.Handle("/", gwmux)
		servePrometheus(httpMux)
		apiHandler = grpcHandlerFunc(grpcServer, httpMux)

		log.Info("grpc server is configured with client certificate authentication")
	} else {
		grpcL := tcpMux.Match(cmux.HTTP2HeaderField("content-type", "application/grpc"))
		apiListener = tcpMux.Match(cmux.Any())
		go func() { handleShutdown(tcpMux.Serve()) }()

		grpcServer := newGrpcServer(store, nil)
		go func() { handleShutdown(grpcServer.Serve(grpcL)) }()

		gwmux := newGrpcGatewayServer(ctx, apiListener.Addr().String(), nil)

		httpMux.Handle("/", gwmux)
		servePrometheus(httpMux)
		apiHandler = httpMux

		log.Warn("grpc server is configured without client certificate authentication")
	}

	srv = &http.Server{
		Handler:   apiHandler,
		TLSConfig: tlsConfig,
	}

	// blocking call
	handleShutdown(srv.Serve(apiListener))
	log.Info("Grpc API stopped")
}

// grpcHandlerFunc returns an http.Handler that delegates to grpcServer on incoming gRPC
// connections or otherHandler otherwise. Copied from cockroachdb.
func grpcHandlerFunc(grpcServer *grpc.Server, otherHandler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor == 2 && strings.Contains(r.Header.Get("Content-Type"), "application/grpc") {
			grpcServer.ServeHTTP(w, r)
		} else {
			otherHandler.ServeHTTP(w, r)
		}
	})
}
