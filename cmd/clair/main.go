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

package main

import (
	"flag"
	"os"
	"runtime/pprof"
	"strings"

	"github.com/coreos/clair"
	"github.com/coreos/clair/config"

	"github.com/coreos/pkg/capnslog"

	// Register components
	_ "github.com/coreos/clair/notifier/notifiers"

	_ "github.com/coreos/clair/updater/fetchers/debian"
	_ "github.com/coreos/clair/updater/fetchers/rhel"
	_ "github.com/coreos/clair/updater/fetchers/ubuntu"
	_ "github.com/coreos/clair/updater/metadata_fetchers/nvd"

	_ "github.com/coreos/clair/worker/detectors/data/aci"
	_ "github.com/coreos/clair/worker/detectors/data/docker"

	_ "github.com/coreos/clair/worker/detectors/feature/dpkg"
	_ "github.com/coreos/clair/worker/detectors/feature/rpm"

	_ "github.com/coreos/clair/worker/detectors/namespace/aptsources"
	_ "github.com/coreos/clair/worker/detectors/namespace/lsbrelease"
	_ "github.com/coreos/clair/worker/detectors/namespace/osrelease"
	_ "github.com/coreos/clair/worker/detectors/namespace/redhatrelease"
)

var log = capnslog.NewPackageLogger("github.com/coreos/clair/cmd/clair", "main")

func main() {
	// Parse command-line arguments
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	flagConfigPath := flag.String("config", "/etc/clair/config.yaml", "Load configuration from the specified file.")
	flagCPUProfilePath := flag.String("cpu-profile", "", "Write a CPU profile to the specified file before exiting.")
	flagLogLevel := flag.String("log-level", "info", "Define the logging level.")
	flag.Parse()
	// Load configuration
	config, err := config.Load(*flagConfigPath)
	if err != nil {
		log.Fatalf("failed to load configuration: %s", err)
	}

	// Initialize logging system
	logLevel, err := capnslog.ParseLevel(strings.ToUpper(*flagLogLevel))
	capnslog.SetGlobalLogLevel(logLevel)
	capnslog.SetFormatter(capnslog.NewPrettyFormatter(os.Stdout, false))

	// Enable CPU Profiling if specified
	if *flagCPUProfilePath != "" {
		defer stopCPUProfiling(startCPUProfiling(*flagCPUProfilePath))
	}

	clair.Boot(config)
}

func startCPUProfiling(path string) *os.File {
	f, err := os.Create(path)
	if err != nil {
		log.Fatalf("failed to create profile file: %s", err)
	}

	err = pprof.StartCPUProfile(f)
	if err != nil {
		log.Fatalf("failed to start CPU profiling: %s", err)
	}

	log.Info("started CPU profiling")

	return f
}

func stopCPUProfiling(f *os.File) {
	pprof.StopCPUProfile()
	f.Close()
	log.Info("stopped CPU profiling")
}
