// Copyright 2019 clair authors
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
		srv.TLSConfig = &tls.Config{
			// This is Go's default list of cipher suites (as of go 1.8.3),
			// with the following differences:
			//
			// - 3DES-based cipher suites have been removed. This cipher is
			//   vulnerable to the Sweet32 attack and is sometimes reported by
			//   security scanners. (This is arguably a false positive since
			//   it will never be selected: Any TLS1.2 implementation MUST
			//   include at least one cipher higher in the priority list, but
			//   there's also no reason to keep it around)
			// - AES is always prioritized over ChaCha20. Go makes this decision
			//   by default based on the presence or absence of hardware AES
			//   acceleration.
			//   TODO(bdarnell): do the same detection here. See
			//   https://github.com/golang/go/issues/21167
			//
			// Note that some TLS cipher suite guidance (such as Mozilla's[1])
			// recommend replacing the CBC_SHA suites below with CBC_SHA384 or
			// CBC_SHA256 variants. We do not do this because Go does not
			// currently implement the CBC_SHA384 suites, and its CBC_SHA256
			// implementation is vulnerable to the Lucky13 attack and is disabled
			// by default.[2]
			//
			// [1]: https://wiki.mozilla.org/Security/Server_Side_TLS#Modern_compatibility
			// [2]: https://github.com/golang/go/commit/48d8edb5b21db190f717e035b4d9ab61a077f9d7
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
				tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
				tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_RSA_WITH_AES_128_CBC_SHA,
				tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			},

			MinVersion: tls.VersionTLS12,
		}
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
