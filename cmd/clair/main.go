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
	"github.com/quay/clair/v4/health"
	"github.com/quay/clair/v4/httptransport"
	"github.com/quay/clair/v4/initialize"
	"github.com/quay/clair/v4/initialize/auto"
	"github.com/quay/clair/v4/introspection"
)

// Version is a version string, injected at build time for release builds.
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
	fail := false
	defer func() {
		if fail {
			os.Exit(1)
		}
	}()

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
	auto.Logs(ctx)

	// Some machinery for starting and stopping server goroutines:
	down := &Shutdown{}
	srvs, srvctx := errgroup.WithContext(ctx)

	// Introspection server goroutine.
	srvs.Go(func() (_ error) {
		zlog.Info(srvctx).Msg("launching introspection server")
		i, err := introspection.New(srvctx, conf, nil)
		if err != nil {
			zlog.Warn(srvctx).
				Err(err).Msg("introspection server configuration failed. continuing anyway")
			return
		}
		down.Add(i.Server)
		if err := i.ListenAndServe(); err != http.ErrServerClosed {
			zlog.Warn(srvctx).
				Err(err).Msg("introspection server failed to launch. continuing anyway")
		}
		return
	})

	// HTTP API server goroutine.
	srvs.Go(func() error {
		zlog.Info(srvctx).Msg("launching http transport")
		srvs, err := initialize.Services(srvctx, &conf)
		if err != nil {
			return fmt.Errorf("service initialization failed: %w", err)
		}
		h, err := httptransport.New(srvctx, conf, srvs.Indexer, srvs.Matcher, srvs.Notifier)
		if err != nil {
			return fmt.Errorf("http transport configuration failed: %w", err)
		}
		down.Add(h.Server)
		health.Ready()
		if err := h.ListenAndServe(); err != http.ErrServerClosed {
			return fmt.Errorf("http transport failed to launch: %w", err)
		}
		return nil
	})

	// Signal handler goroutine.
	srvs.Go(func() error {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt)
		defer func() {
			signal.Stop(c)
			close(c)
			zlog.Info(ctx).Msg("unregistered signal handler")
		}()
		zlog.Info(ctx).Msg("registered signal handler")
		select {
		case sig := <-c:
			zlog.Info(ctx).
				Stringer("signal", sig).
				Msg("gracefully shutting down")
			// Note that we're using the root context here, so that we get a
			// full timeout if one errgroup goroutine returns uncleanly.
			tctx, done := context.WithTimeout(ctx, 10*time.Second)
			err := down.Shutdown(tctx)
			done()
			if err != nil {
				zlog.Error(ctx).Err(err).Msg("error shutting down server")
			}
		case <-srvctx.Done():
		}
		return nil
	})
	// Spawn a goroutine outside to wait on the errgroup.
	//
	// This is needed to call shutdown and cause the servers to return when only
	// one has returned an error.
	go func() {
		<-srvctx.Done()
		tctx, done := context.WithTimeout(ctx, 10*time.Second)
		err := down.Shutdown(tctx)
		done()
		if err != nil {
			zlog.Error(ctx).Err(err).Msg("error shutting down server")
		}
	}()

	zlog.Info(ctx).Str("version", Version).Msg("ready")
	if err := srvs.Wait(); err != nil {
		zlog.Error(ctx).Err(err).Msg("fatal error")
		fail = true
	}
}
