package main

import (
	"context"
	"flag"
	golog "log"
	"os"
	"os/signal"
	"time"

	"github.com/rs/zerolog"
	yaml "gopkg.in/yaml.v3"

	"github.com/quay/clair/v4/config"
	"github.com/quay/clair/v4/initialize"
	_ "github.com/quay/claircore/updater/defaults"
)

// Version is a version string, optionally injected at build time.
var Version string

const (
	envConfig = `CLAIR_CONF`
	envMode   = `CLAIR_MODE`
)

func main() {
	// parse conf from cli
	var (
		confFile ConfValue
		conf     config.Config
		runMode  ConfMode
	)
	confFile.Set(os.Getenv(envConfig))
	runMode.Set(os.Getenv(envMode))
	flag.Var(&confFile, "conf", "The file system path to Clair's config file.")
	flag.Var(&runMode, "mode", "The operation mode for this server.")
	flag.Parse()
	if confFile.String() == "" {
		golog.Fatalf("must provide a -conf flag or set %q in the environment", envConfig)
	}

	// validate config
	err := yaml.NewDecoder(confFile.file).Decode(&conf)
	if err != nil {
		golog.Fatalf("failed to decode yaml config: %v", err)
	}
	conf.Mode = runMode.String()
	err = config.Validate(&conf)
	if err != nil {
		golog.Fatalf("failed to validate config: %v", err)
	}

	// initialize performs all Clair initialization tasks.
	init, err := initialize.New(conf)
	if err != nil {
		golog.Fatalf("initialized failed: %v", err)
	}
	logger := zerolog.Ctx(init.GlobalCTX).With().Str("component", "main").Logger()

	// register signal handler
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	logger.Info().Msg("registered signal handler")

	// introspection server
	if init.Introspection != nil {
		logger.Info().Msg("launching introspection server")
		go func() {
			err := init.Introspection.ListenAndServe()
			if err != nil {
				logger.Err(err).Msg("introspection server failed to launch. continuing anyway")
			}
		}()
	}

	// http transport
	logger.Info().Msg("launching http transport")
	go func() {
		err := init.HttpTransport.ListenAndServe()
		if err != nil {
			logger.Err(err).Msg("http transport failed to listen and serve")
			init.GlobalCancel()
		}
	}()

	// block on signal
	logger.Info().Str("version", Version).Msg("ready")
	select {
	case sig := <-c:
		// received a SIGINT for graceful shutdown
		logger.Info().
			Str("signal", sig.String()).
			Msg("gracefully shutting down")
		tctx, cancel := context.WithTimeout(init.GlobalCTX, 10*time.Second)
		defer cancel()
		init.HttpTransport.Shutdown(tctx)
		// cancel the entire application root ctx
		init.GlobalCancel()
	case <-init.GlobalCTX.Done():
		// main cancel func called indicating error initializing
		logger.Fatal().Msg("initialization failed")
	}
}
