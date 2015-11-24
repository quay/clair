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
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
)

// LoadTLSClientConfig initializes a *tls.Config using the given certificates and private key, that
// can be used to communicate with a server using client certificate authentificate.
//
// If no certificates are given, a nil *tls.Config is returned.
// The CA certificate is optionnal, the system defaults are used if not provided.
func LoadTLSClientConfig(certFile, keyFile, caFile string) (*tls.Config, error) {
	if len(certFile) == 0 || len(keyFile) == 0 {
		return nil, nil
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}

	var caCertPool *x509.CertPool
	if len(caFile) > 0 {
		caCert, err := ioutil.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		caCertPool = x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
	}

	return tlsConfig, nil
}
