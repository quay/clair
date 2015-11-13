// Copyright 2015 quay-sec authors
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

package main

import (
	"math/rand"
	"os"
	"os/signal"
	"runtime/pprof"
	"strings"
	"time"

	"github.com/coreos/quay-sec/api"
	"github.com/coreos/quay-sec/database"
	"github.com/coreos/quay-sec/notifier"
	"github.com/coreos/quay-sec/updater"
	"github.com/coreos/quay-sec/utils"

	"github.com/coreos/pkg/capnslog"
	"gopkg.in/alecthomas/kingpin.v2"

	// Register components
	_ "github.com/coreos/quay-sec/updater/fetchers"
	_ "github.com/coreos/quay-sec/worker/detectors/os"
	_ "github.com/coreos/quay-sec/worker/detectors/packages"
)

var (
	log = capnslog.NewPackageLogger("github.com/coreos/quay-sec", "main")

	// Database configuration
	cfgDbType = kingpin.Flag("db-type", "Type of the database to use").Default("bolt").Enum("bolt", "leveldb", "memstore", "mongo", "sql")
	cfgDbPath = kingpin.Flag("db-path", "Path to the database to use").String()

	// Notifier configuration
	cfgNotifierType    = kingpin.Flag("notifier-type", "Type of the notifier to use").Default("none").Enum("none", "http")
	cfgNotifierHTTPURL = kingpin.Flag("notifier-http-url", "URL that will receive POST notifications").String()

	// Updater configuration
	cfgUpdateInterval = kingpin.Flag("update-interval", "Frequency at which the vulnerability updater will run. Use 0 to disable the updater entirely.").Default("1h").Duration()

	// API configuration
	cfgAPIPort     = kingpin.Flag("api-port", "Port on which the API will listen").Default("6060").Int()
	cfgAPITimeout  = kingpin.Flag("api-timeout", "Timeout of API calls").Default("900s").Duration()
	cfgAPICertFile = kingpin.Flag("api-cert-file", "Path to TLS Cert file").ExistingFile()
	cfgAPIKeyFile  = kingpin.Flag("api-key-file", "Path to TLS Key file").ExistingFile()
	cfgAPICAFile   = kingpin.Flag("api-ca-file", "Path to CA for verifying TLS client certs").ExistingFile()

	// Other flags
	cfgCPUProfilePath = kingpin.Flag("cpu-profile-path", "Path to a write CPU profiling data").String()
	cfgLogLevel       = kingpin.Flag("log-level", "How much console-spam do you want globally").Default("info").Enum("trace", "debug", "info", "notice", "warning", "error", "critical")
)

func main() {
	rand.Seed(time.Now().UTC().UnixNano())

	var err error
	st := utils.NewStopper()

	// Parse command-line arguments
	kingpin.Parse()
	if *cfgDbType != "memstore" && *cfgDbPath == "" {
		kingpin.Errorf("required flag --db-path not provided, try --help")
		os.Exit(1)
	}
	if *cfgNotifierType == "http" && *cfgNotifierHTTPURL == "" {
		kingpin.Errorf("required flag --notifier-http-url not provided, try --help")
		os.Exit(1)
	}

	// Initialize error/logging system
	logLevel, err := capnslog.ParseLevel(strings.ToUpper(*cfgLogLevel))
	capnslog.SetGlobalLogLevel(logLevel)
	capnslog.SetFormatter(capnslog.NewPrettyFormatter(os.Stdout, false))

	// Enable CPU Profiling if specified
	if *cfgCPUProfilePath != "" {
		f, err := os.Create(*cfgCPUProfilePath)
		if err != nil {
			log.Fatalf("failed to create profile file: %s", err)
		}
		defer f.Close()

		pprof.StartCPUProfile(f)
		log.Info("started profiling")

		defer func() {
			pprof.StopCPUProfile()
			log.Info("stopped profiling")
		}()
	}

	// Open database
	err = database.Open(*cfgDbType, *cfgDbPath)
	if err != nil {
		log.Fatal(err)
	}
	defer database.Close()

	// Start notifier
	var notifierService notifier.Notifier
	switch *cfgNotifierType {
	case "http":
		notifierService, err = notifier.NewHTTPNotifier(*cfgNotifierHTTPURL)
		if err != nil {
			log.Fatalf("could not initialize HTTP notifier: %s", err)
		}
	}
	if notifierService != nil {
		st.Begin()
		go notifierService.Run(st)
	}

	// Start Main API and Health API
	st.Begin()
	go api.RunMain(&api.Config{
		Port:     *cfgAPIPort,
		TimeOut:  *cfgAPITimeout,
		CertFile: *cfgAPICertFile,
		KeyFile:  *cfgAPIKeyFile,
		CAFile:   *cfgAPICAFile,
	}, st)
	st.Begin()
	go api.RunHealth(*cfgAPIPort+1, st)

	// Start updater
	st.Begin()
	go updater.Run(*cfgUpdateInterval, st)

	// This blocks the main goroutine which is required to keep all the other goroutines running
	interrupts := make(chan os.Signal, 1)
	signal.Notify(interrupts, os.Interrupt)
	<-interrupts
	log.Info("Received interruption, gracefully stopping ...")
	st.Stop()
}
