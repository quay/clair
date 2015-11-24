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

// Package api provides a RESTful HTTP API, enabling external apps to interact
// with clair.
package api

import (
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/coreos/pkg/capnslog"
	"github.com/tylerb/graceful"

	"github.com/coreos/clair/utils"
	httputils "github.com/coreos/clair/utils/http"
)

var log = capnslog.NewPackageLogger("github.com/coreos/clair", "api")

// Config represents the configuration for the Main API.
type Config struct {
	Port                      int
	TimeOut                   time.Duration
	CertFile, KeyFile, CAFile string
}

// RunMain launches the main API, which exposes every possible interactions
// with clair.
func RunMain(conf *Config, st *utils.Stopper) {
	log.Infof("starting API on port %d.", conf.Port)
	defer func() {
		log.Info("API stopped")
		st.End()
	}()

	tlsConfig, err := httputils.LoadTLSClientConfigForServer(conf.CAFile)
	if err != nil {
		log.Fatalf("could not initialize client cert authentification: %s\n", err)
	}
	if tlsConfig != nil {
		log.Info("api configured with client certificate authentification")
	}

	srv := &graceful.Server{
		Timeout:          0,    // Already handled by our TimeOut middleware
		NoSignalHandling: true, // We want to use our own Stopper
		Server: &http.Server{
			Addr:      ":" + strconv.Itoa(conf.Port),
			TLSConfig: tlsConfig,
			Handler:   NewVersionRouter(conf.TimeOut),
		},
	}
	listenAndServeWithStopper(srv, st, conf.CertFile, conf.KeyFile)
}

// RunHealth launches the Health API, which only exposes a method to fetch
// clair's health without any security or authentification mechanism.
func RunHealth(port int, st *utils.Stopper) {
	log.Infof("starting Health API on port %d.", port)
	defer func() {
		log.Info("Health API stopped")
		st.End()
	}()

	srv := &graceful.Server{
		Timeout:          10 * time.Second, // Interrupt health checks when stopping
		NoSignalHandling: true,             // We want to use our own Stopper
		Server: &http.Server{
			Addr:    ":" + strconv.Itoa(port),
			Handler: NewHealthRouter(),
		},
	}
	listenAndServeWithStopper(srv, st, "", "")
}

// listenAndServeWithStopper wraps graceful.Server's
// ListenAndServe/ListenAndServeTLS and adds the ability to interrupt them with
// the provided utils.Stopper
func listenAndServeWithStopper(srv *graceful.Server, st *utils.Stopper, certFile, keyFile string) {
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

	if opErr, ok := err.(*net.OpError); !ok || (ok && opErr.Op != "accept") {
		log.Fatal(err)
	}
}
