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

package api

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"net"
	"net/http"
	"strconv"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/tylerb/graceful"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/pkg/stopper"
)

const timeoutResponse = `{"Error":{"Message":"Clair failed to respond within the configured timeout window.","Type":"Timeout"}}`

// Config is the configuration for the API service.
type Config struct {
	Port                      int
	HealthPort                int
	Timeout                   time.Duration
	PaginationKey             string
	CertFile, KeyFile, CAFile string
}

func Run(cfg *Config, store database.Datastore, st *stopper.Stopper) {
	defer st.End()

	// Do not run the API service if there is no config.
	if cfg == nil {
		log.Info("main API service is disabled.")
		return
	}
	log.WithField("port", cfg.Port).Info("starting main API")

	tlsConfig, err := tlsClientConfig(cfg.CAFile)
	if err != nil {
		log.WithError(err).Fatal("could not initialize client cert authentication")
	}
	if tlsConfig != nil {
		log.Info("main API configured with client certificate authentication")
	}

	srv := &graceful.Server{
		Timeout:          0,    // Already handled by our TimeOut middleware
		NoSignalHandling: true, // We want to use our own Stopper
		Server: &http.Server{
			Addr:      ":" + strconv.Itoa(cfg.Port),
			TLSConfig: tlsConfig,
			Handler:   http.TimeoutHandler(newAPIHandler(cfg, store), cfg.Timeout, timeoutResponse),
		},
	}

	listenAndServeWithStopper(srv, st, cfg.CertFile, cfg.KeyFile)

	log.Info("main API stopped")
}

func RunHealth(cfg *Config, store database.Datastore, st *stopper.Stopper) {
	defer st.End()

	// Do not run the API service if there is no config.
	if cfg == nil {
		log.Info("health API service is disabled.")
		return
	}
	log.WithField("port", cfg.HealthPort).Info("starting health API")

	srv := &graceful.Server{
		Timeout:          10 * time.Second, // Interrupt health checks when stopping
		NoSignalHandling: true,             // We want to use our own Stopper
		Server: &http.Server{
			Addr:    ":" + strconv.Itoa(cfg.HealthPort),
			Handler: http.TimeoutHandler(newHealthHandler(store), cfg.Timeout, timeoutResponse),
		},
	}

	listenAndServeWithStopper(srv, st, "", "")

	log.Info("health API stopped")
}

// listenAndServeWithStopper wraps graceful.Server's
// ListenAndServe/ListenAndServeTLS and adds the ability to interrupt them with
// the provided stopper.Stopper.
func listenAndServeWithStopper(srv *graceful.Server, st *stopper.Stopper, certFile, keyFile string) {
	go func() {
		<-st.Chan()
		srv.Stop(0)
	}()

	var err error
	if certFile != "" && keyFile != "" {
		log.Info("API: TLS Enabled")
		err = srv.ListenAndServeTLS(certFile, keyFile)
	} else {
		err = srv.ListenAndServe()
	}

	if err != nil {
		if opErr, ok := err.(*net.OpError); !ok || (ok && opErr.Op != "accept") {
			log.Fatal(err)
		}
	}
}

// tlsClientConfig initializes a *tls.Config using the given CA. The resulting
// *tls.Config is meant to be used to configure an HTTP server to do client
// certificate authentication.
//
// If no CA is given, a nil *tls.Config is returned; no client certificate will
// be required and verified. In other words, authentication will be disabled.
func tlsClientConfig(caPath string) (*tls.Config, error) {
	if caPath == "" {
		return nil, nil
	}

	caCert, err := ioutil.ReadFile(caPath)
	if err != nil {
		return nil, err
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	tlsConfig := &tls.Config{
		ClientCAs:  caCertPool,
		ClientAuth: tls.RequireAndVerifyClientCert,

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
		// currerntly implement the CBC_SHA384 suites, and its CBC_SHA256
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

	return tlsConfig, nil
}
