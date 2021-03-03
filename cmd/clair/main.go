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
	"github.com/quay/zlog"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/label"
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

	if err := initialize.Logging(ctx, &conf); err != nil {
		golog.Fatalf("failed to set up logging: %v", err)
	}
	ctx = baggage.ContextWithValues(ctx, label.String("component", "main"))
	zlog.Info(ctx).
		Str("version", Version).
		Msg("starting")

	// Some machinery for starting and stopping server goroutines
	down := &Shutdown{}
	srvs, srvctx := errgroup.WithContext(ctx)

	srvs.Go(func() (_ error) {
		zlog.Info(ctx).Msg("launching introspection server")
		i, err := introspection.New(ctx, conf, nil)
		if err != nil {
			zlog.Warn(ctx).
				Err(err).Msg("introspection server configuration failed. continuing anyway")
			return
		}
		down.Add(i.Server)
		if err := i.ListenAndServe(); err != http.ErrServerClosed {
			zlog.Warn(ctx).
				Err(err).Msg("introspection server failed to launch. continuing anyway")
		}
		return
	})

	srvs.Go(func() error {
		zlog.Info(ctx).Msg("launching http transport")
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
	zlog.Info(ctx).Msg("registered signal handler")
	zlog.Info(ctx).Str("version", Version).Msg("ready")
	select {
	case sig := <-c:
		zlog.Info(ctx).
			Stringer("signal", sig).
			Msg("gracefully shutting down")
		tctx, done := context.WithTimeout(ctx, 10*time.Second)
		err := down.Shutdown(tctx)
		done()
		if err != nil {
			zlog.Error(ctx).Err(err).Msg("error shutting down server")
		}
	case <-srvctx.Done():
		zlog.Error(ctx).Err(srvctx.Err()).Msg("initialization failed")
		os.Exit(1)
	}
}
