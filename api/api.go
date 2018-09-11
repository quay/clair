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

package api

import (
	"context"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"

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
	err := v3.ListenAndServe(cfg.Addr, cfg.CertFile, cfg.KeyFile, cfg.CAFile, store)
	if err != nil {
		log.WithError(err).Fatal("could not initialize gRPC server")
	}
}

func RunHealth(cfg *Config, store database.Datastore, st *stopper.Stopper) {
	defer st.End()

	// Do not run the API service if there is no config.
	if cfg == nil {
		log.Info("health API service is disabled.")
		return
	}
	log.WithField("addr", cfg.HealthAddr).Info("starting health API")

	srv := http.Server{
		Addr:    cfg.HealthAddr,
		Handler: http.TimeoutHandler(newHealthHandler(store), cfg.Timeout, timeoutResponse),
	}

	go func() {
		<-st.Chan()
		srv.Shutdown(context.TODO())
	}()

	err := srv.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}

	log.Info("health API stopped")
}
