package main

import (
	"context"
	"flag"
	"fmt"
	golog "log"
	"net/http"
	"os"
	"os/signal"
	"time"

	_ "github.com/quay/claircore/updater/defaults"
	"github.com/rs/zerolog"
	"golang.org/x/sync/errgroup"
	yaml "gopkg.in/yaml.v3"

	"github.com/quay/clair/v4/config"
	"github.com/quay/clair/v4/httptransport"
	"github.com/quay/clair/v4/initialize"
	"github.com/quay/clair/v4/introspection"
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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ctx, err = initialize.Logging(ctx, &conf)
	if err != nil {
		golog.Fatalf("failed to set up logging: %v", err)
	}
	logger := zerolog.Ctx(ctx).With().Str("component", "main").Logger()
	logger.Info().Str("version", Version).Msg("starting")

	// Some machinery for starting and stopping server goroutines
	down := &Shutdown{}
	srvs, srvctx := errgroup.WithContext(ctx)

	srvs.Go(func() (_ error) {
		logger.Info().Msg("launching introspection server")
		i, err := introspection.New(ctx, conf, nil)
		if err != nil {
			logger.Warn().
				Err(err).Msg("introspection server configuration failed. continuing anyway")
			return
		}
		down.Add(i.Server)
		if err := i.ListenAndServe(); err != http.ErrServerClosed {
			logger.Warn().
				Err(err).Msg("introspection server failed to launch. continuing anyway")
		}
		return
	})

	srvs.Go(func() error {
		logger.Info().Msg("launching http transport")
		srvs, err := initialize.Services(ctx, &conf)
		if err != nil {
			return fmt.Errorf("service initialization failed: %w", err)
		}
		h, err := httptransport.New(ctx, conf, srvs.Indexer, srvs.Matcher, srvs.Notifier)
		if err != nil {
			return fmt.Errorf("http transport configuration failed: %w", err)
		}
		down.Add(h.Server)
		if err := h.ListenAndServe(); err != http.ErrServerClosed {
			return fmt.Errorf("http transport failed to launch: %w", err)
		}
		return nil
	})

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	logger.Info().Msg("registered signal handler")
	logger.Info().Str("version", Version).Msg("ready")
	select {
	case sig := <-c:
		logger.Info().
			Str("signal", sig.String()).
			Msg("gracefully shutting down")
		tctx, done := context.WithTimeout(ctx, 10*time.Second)
		err := down.Shutdown(tctx)
		done()
		if err != nil {
			logger.Error().Err(err).Msg("error shutting down server")
		}
	case <-srvctx.Done():
		logger.Error().Err(srvctx.Err()).Msg("initialization failed")
		os.Exit(1)
	}
}
