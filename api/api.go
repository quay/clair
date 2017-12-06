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
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/tylerb/graceful"

	"github.com/coreos/clair/api/v3"
	"github.com/coreos/clair/database"
	"github.com/coreos/clair/pkg/stopper"
)

const timeoutResponse = `{"Error":{"Message":"Clair failed to respond within the configured timeout window.","Type":"Timeout"}}`

// Config is the configuration for the API service.
type Config struct {
	Addr                      string
	HealthAddr                string
	Timeout                   time.Duration
	CertFile, KeyFile, CAFile string
}

func Run(cfg *Config, store database.Datastore) {
	tlsConfig, err := tlsClientConfig(cfg.CAFile)
	if err != nil {
		log.WithError(err).Fatal("could not initialize client cert authentication")
	}
	if tlsConfig != nil {
		log.Info("main API configured with client certificate authentication")
	}
	v3.Run(cfg.Addr, tlsConfig, cfg.CertFile, cfg.KeyFile, store)
}

func RunHealth(cfg *Config, store database.Datastore, st *stopper.Stopper) {
	defer st.End()

	// Do not run the API service if there is no config.
	if cfg == nil {
		log.Info("health API service is disabled.")
		return
	}
	log.WithField("addr", cfg.HealthAddr).Info("starting health API")

	srv := &graceful.Server{
		Timeout:          10 * time.Second, // Interrupt health checks when stopping
		NoSignalHandling: true,             // We want to use our own Stopper
		Server: &http.Server{
			Addr:    cfg.HealthAddr,
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
	}

	return tlsConfig, nil
}
