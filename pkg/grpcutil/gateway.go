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

package grpcutil

import (
	"crypto/tls"
	"net/http"
	"strings"

	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// RegisterServiceHandlerFunc is a function that registers ServiceHandlers with
// a ServeMux.
type RegisterServiceHandlerFunc func(context.Context, *runtime.ServeMux, *grpc.ClientConn) error

// NewGateway creates a new http.Handler and grpc.ClientConn with the provided
// gRPC Services registered.
func NewGateway(addr string, tlsConfig *tls.Config, funcs []RegisterServiceHandlerFunc) (http.Handler, *grpc.ClientConn, error) {
	// Configure the right DialOptions the for TLS configuration.
	var dialOpts []grpc.DialOption
	if tlsConfig != nil {
		var gwTLSConfig *tls.Config
		gwTLSConfig = tlsConfig.Clone()
		gwTLSConfig.InsecureSkipVerify = true // Trust the local server.
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(credentials.NewTLS(gwTLSConfig)))
	} else {
		dialOpts = append(dialOpts, grpc.WithInsecure())
	}

	conn, err := grpc.DialContext(context.TODO(), addr, dialOpts...)
	if err != nil {
		return nil, nil, err
	}

	// Register services.
	srvmux := runtime.NewServeMux()
	for _, fn := range funcs {
		err = fn(context.TODO(), srvmux, conn)
		if err != nil {
			return nil, nil, err
		}
	}

	return srvmux, conn, nil
}

// IsGRPCRequest returns true if the provided request came from a gRPC client.
//
// Its logic is a partial recreation of gRPC's internal checks, see:
// https://github.com/grpc/grpc-go/blob/01de3de/transport/handler_server.go#L61:L69
func IsGRPCRequest(r *http.Request) bool {
	return r.ProtoMajor == 2 && strings.Contains(r.Header.Get("Content-Type"), "application/grpc")
}

// HandlerFunc returns an http.Handler that delegates to grpc.Server on
// incoming gRPC connections otherwise serves with the provided handler.
func HandlerFunc(grpcServer *grpc.Server, otherwise http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if IsGRPCRequest(r) {
			grpcServer.ServeHTTP(w, r)
		} else {
			otherwise.ServeHTTP(w, r)
		}
	})
}
