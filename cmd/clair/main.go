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

package main

import (
	"flag"
	"math/rand"
	"os"
	"os/exec"
	"os/signal"
	"runtime/pprof"
	"strings"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/coreos/clair"
	"github.com/coreos/clair/api"
	"github.com/coreos/clair/database"
	"github.com/coreos/clair/ext/imagefmt"
	"github.com/coreos/clair/pkg/formatter"
	"github.com/coreos/clair/pkg/stopper"

	// Register database driver.
	_ "github.com/coreos/clair/database/pgsql"

	// Register extensions.
	_ "github.com/coreos/clair/ext/featurefmt/apk"
	_ "github.com/coreos/clair/ext/featurefmt/dpkg"
	_ "github.com/coreos/clair/ext/featurefmt/rpm"
	_ "github.com/coreos/clair/ext/featurens/alpinerelease"
	_ "github.com/coreos/clair/ext/featurens/aptsources"
	_ "github.com/coreos/clair/ext/featurens/lsbrelease"
	_ "github.com/coreos/clair/ext/featurens/osrelease"
	_ "github.com/coreos/clair/ext/featurens/redhatrelease"
	_ "github.com/coreos/clair/ext/imagefmt/aci"
	_ "github.com/coreos/clair/ext/imagefmt/docker"
	_ "github.com/coreos/clair/ext/notification/webhook"
	_ "github.com/coreos/clair/ext/vulnmdsrc/nvd"
	_ "github.com/coreos/clair/ext/vulnsrc/alpine"
	_ "github.com/coreos/clair/ext/vulnsrc/debian"
	_ "github.com/coreos/clair/ext/vulnsrc/oracle"
	_ "github.com/coreos/clair/ext/vulnsrc/rhel"
	_ "github.com/coreos/clair/ext/vulnsrc/ubuntu"
)

func waitForSignals(signals ...os.Signal) {
	interrupts := make(chan os.Signal, 1)
	signal.Notify(interrupts, signals...)
	<-interrupts
}

func startCPUProfiling(path string) *os.File {
	f, err := os.Create(path)
	if err != nil {
		log.WithError(err).Fatal("failed to create profile file")
	}

	err = pprof.StartCPUProfile(f)
	if err != nil {
		log.WithError(err).Fatal("failed to start CPU profiling")
	}

	log.Info("started CPU profiling")

	return f
}

func stopCPUProfiling(f *os.File) {
	pprof.StopCPUProfile()
	f.Close()
	log.Info("stopped CPU profiling")
}

// Boot starts Clair instance with the provided config.
func Boot(config *Config) {
	rand.Seed(time.Now().UnixNano())
	st := stopper.NewStopper()

	// Open database
	db, err := database.Open(config.Database)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Start notifier
	st.Begin()
	go clair.RunNotifier(config.Notifier, db, st)

	// Start API
	st.Begin()
	go api.Run(config.API, db, st)
	st.Begin()
	go api.RunHealth(config.API, db, st)

	// Start updater
	st.Begin()
	go clair.RunUpdater(config.Updater, db, st)

	// Wait for interruption and shutdown gracefully.
	waitForSignals(syscall.SIGINT, syscall.SIGTERM)
	log.Info("Received interruption, gracefully stopping ...")
	st.Stop()
}

func main() {
	// Parse command-line arguments
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	flagConfigPath := flag.String("config", "/etc/clair/config.yaml", "Load configuration from the specified file.")
	flagCPUProfilePath := flag.String("cpu-profile", "", "Write a CPU profile to the specified file before exiting.")
	flagLogLevel := flag.String("log-level", "info", "Define the logging level.")
	flagInsecureTLS := flag.Bool("insecure-tls", false, "Disable TLS server's certificate chain and hostname verification when pulling layers.")
	flag.Parse()

	// Check for dependencies.
	for _, bin := range []string{"git", "bzr", "rpm", "xz"} {
		_, err := exec.LookPath(bin)
		if err != nil {
			log.WithError(err).WithField("dependency", bin).Fatal("failed to find dependency")
		}
	}

	// Load configuration
	config, err := LoadConfig(*flagConfigPath)
	if err != nil {
		log.WithError(err).Fatal("failed to load configuration")
	}

	// Initialize logging system

	logLevel, err := log.ParseLevel(strings.ToUpper(*flagLogLevel))
	log.SetLevel(logLevel)
	log.SetOutput(os.Stdout)
	log.SetFormatter(&formatter.JSONExtendedFormatter{ShowLn: true})

	// Enable CPU Profiling if specified
	if *flagCPUProfilePath != "" {
		defer stopCPUProfiling(startCPUProfiling(*flagCPUProfilePath))
	}

	// Enable TLS server's certificate chain and hostname verification
	// when pulling layers if specified
	if *flagInsecureTLS {
		imagefmt.SetInsecureTLS(*flagInsecureTLS)
	}

	Boot(config)
}
