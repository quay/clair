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

// Package grpcutil implements various utilities around managing gRPC services.
package grpcutil

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"net"
	"net/http"

	"github.com/cockroachdb/cmux"

	"github.com/coreos/clair/pkg/httputil"
)

// MuxedGRPCServer defines the parameters for running a gRPC Server alongside
// a Gateway server on the same port.
type MuxedGRPCServer struct {
	Addr                string
	TLSConfig           *tls.Config
	ServicesFunc        RegisterServicesFunc
	ServiceHandlerFuncs []RegisterServiceHandlerFunc
}

// ListenAndServe listens on the TCP network address srv.Addr and handles both
// gRPC and JSON requests over HTTP. An optional HTTP middleware can be
// provided to wrap the output of each request.
//
// Internally, it muxes the Listener based on whether the request is gRPC or
// HTTP and runs multiple servers.
func (srv *MuxedGRPCServer) ListenAndServe(mw httputil.Middleware) error {
	l, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		return err
	}

	tcpMux := cmux.New(l)

	grpcListener := tcpMux.Match(cmux.HTTP2HeaderField("content-type", "application/grpc"))
	defer grpcListener.Close()

	httpListener := tcpMux.Match(cmux.Any())
	defer httpListener.Close()

	httpHandler, conn, err := NewGateway(httpListener.Addr().String(), nil, srv.ServiceHandlerFuncs)
	if err != nil {
		return err
	}
	defer conn.Close()

	gsrv := NewServer(nil, srv.ServicesFunc)
	defer gsrv.Stop()

	go func() { tcpMux.Serve() }()
	go func() { gsrv.Serve(grpcListener) }()

	if mw != nil {
		httpHandler = mw(httpHandler)
	}

	httpsrv := &http.Server{
		Handler: httpHandler,
	}
	httpsrv.Serve(httpListener)
	return nil
}

func configureCA(tlsConfig *tls.Config, caPath string) error {
	caCert, err := ioutil.ReadFile(caPath)
	if err != nil {
		return err
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	tlsConfig.ClientCAs = caCertPool
	tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert

	return nil
}

func configureCertificate(tlsConfig *tls.Config, certFile, keyFile string) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}

	tlsConfig.Certificates = []tls.Certificate{cert}
	tlsConfig.NextProtos = []string{"h2"}

	return nil
}

// ListenAndServeTLS listens on the TCP network address srv.Addr and handles both
// gRPC and JSON requests over HTTP over TLS. An optional HTTP middleware can
// be provided to wrap the output of each request.
//
// Internally, the same net.Listener is used because the http.Handler will
// pivot based on whether the request is gRPC or HTTP.
func (srv *MuxedGRPCServer) ListenAndServeTLS(certFile, keyFile, caPath string, mw httputil.Middleware) error {
	if srv.TLSConfig == nil {
		srv.TLSConfig = &tls.Config{}
	}
	err := configureCA(srv.TLSConfig, caPath)
	if err != nil {
		return err
	}
	err = configureCertificate(srv.TLSConfig, certFile, keyFile)
	if err != nil {
		return err
	}

	listener, err := tls.Listen("tcp", srv.Addr, srv.TLSConfig)
	if err != nil {
		return err
	}

	gwHandler, conn, err := NewGateway(listener.Addr().String(), srv.TLSConfig, srv.ServiceHandlerFuncs)
	if err != nil {
		return err
	}
	defer conn.Close()

	gsrv := NewServer(srv.TLSConfig, srv.ServicesFunc)
	defer gsrv.Stop()

	httpHandler := HandlerFunc(gsrv, gwHandler)
	if mw != nil {
		httpHandler = mw(httpHandler)
	}

	httpsrv := &http.Server{
		Handler: httpHandler,
	}
	httpsrv.Serve(listener)
	return nil
}
