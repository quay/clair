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

	"github.com/grpc-ecosystem/go-grpc-prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// RegisterServicesFunc is a function that registers gRPC services with a given
// server.
type RegisterServicesFunc func(*grpc.Server)

// NewServer allocates a new grpc.Server and handles some some boilerplate
// configuration.
func NewServer(tlsConfig *tls.Config, fn RegisterServicesFunc) *grpc.Server {
	// Default ServerOptions
	grpcOpts := []grpc.ServerOption{
		grpc.UnaryInterceptor(grpc_prometheus.UnaryServerInterceptor),
		grpc.StreamInterceptor(grpc_prometheus.StreamServerInterceptor),
	}

	if tlsConfig != nil {
		grpcOpts = append(grpcOpts, grpc.Creds(credentials.NewTLS(tlsConfig)))
	}

	// Register services with a new grpc.Server.
	gsrv := grpc.NewServer(grpcOpts...)
	fn(gsrv)
	return gsrv
}
