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

// Package clair implements the ability to boot Clair with your own imports
// that can dynamically register additional functionality.
package clair

import (
	"math/rand"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/coreos/clair/api"
	"github.com/coreos/clair/api/context"
	"github.com/coreos/clair/config"
	"github.com/coreos/clair/notifier"
	"github.com/coreos/clair/services/keyvalue"
	"github.com/coreos/clair/services/layers"
	"github.com/coreos/clair/services/locks"
	"github.com/coreos/clair/services/namespaces"
	"github.com/coreos/clair/services/notifications"
	"github.com/coreos/clair/services/vulnerabilities"
	"github.com/coreos/clair/updater"
	"github.com/coreos/clair/utils"
	"github.com/coreos/pkg/capnslog"
)

var log = capnslog.NewPackageLogger("github.com/coreos/clair", "main")

// Boot starts Clair. By exporting this function, anyone can import their own
// custom fetchers/updaters into their own package and then call clair.Boot.
func Boot(config *config.Config) {
	rand.Seed(time.Now().UnixNano())
	st := utils.NewStopper()

	// Open services
	ls, err := locks.Open(config.Database)
	if err != nil {
		log.Fatal(err)
	}
	defer ls.Close()

	kvs, err := keyvalue.Open(config.Database)
	if err != nil {
		log.Fatal(err)
	}
	defer kvs.Close()

	vuln, err := vulnerabilities.Open(config.Database)
	if err != nil {
		log.Fatal(err)
	}
	defer vuln.Close()

	layers, err := layers.Open(config.Database)
	if err != nil {
		log.Fatal(err)
	}
	defer layers.Close()

	names, err := namespaces.Open(config.Database)
	if err != nil {
		log.Fatal(err)
	}
	defer names.Close()

	ns, err := notifications.Open(config.Database)
	if err != nil {
		log.Fatal(err)
	}
	defer ns.Close()

	// Start notifier
	st.Begin()
	go notifier.Run(config.Notifier, ls, ns, st)

	// Start API
	st.Begin()
	ctx := &context.RouteContext{ls, kvs, vuln, layers, names, ns, config.API}
	go api.Run(config.API, ctx, st)
	st.Begin()
	go api.RunHealth(config.API, ctx, st)

	// Start updater
	st.Begin()
	go updater.Run(config.Updater, ls, kvs, vuln, st)

	// Wait for interruption and shutdown gracefully.
	waitForSignals(syscall.SIGINT, syscall.SIGTERM)
	log.Info("Received interruption, gracefully stopping ...")
	st.Stop()
}

func waitForSignals(signals ...os.Signal) {
	interrupts := make(chan os.Signal, 1)
	signal.Notify(interrupts, signals...)
	<-interrupts
}
