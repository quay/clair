package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	golog "log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/quay/clair/config"
	_ "github.com/quay/claircore/updater/defaults"
	"github.com/quay/zlog"
	"golang.org/x/sync/errgroup"

	"github.com/quay/clair/v4/cmd"
	"github.com/quay/clair/v4/health"
	"github.com/quay/clair/v4/httptransport"
	"github.com/quay/clair/v4/initialize"
	"github.com/quay/clair/v4/initialize/auto"
	"github.com/quay/clair/v4/introspection"
)

const (
	envConfig = `CLAIR_CONF`
	envMode   = `CLAIR_MODE`
)

func main() {
	// parse conf from cli
	var conf config.Config
	flag.String("conf", "", "The file system path to Clair's config file.")
	flag.String("mode", "", "The operation mode for this server, will default to combo.")
	flag.Parse()
	flag.VisitAll(func(f *flag.Flag) {
		fv := f.Value.(flag.Getter).Get().(string)
		var key string
		switch f.Name {
		case "conf":
			key = envConfig
		case "mode":
			key = envMode
		}
		v, ok := os.LookupEnv(key)
		if fv == "" && !ok {
			golog.Fatalf("must provide a -%s value or set %q in the environment", f.Name, key)
		}
		if fv == "" && ok {
			fv = v
		}
		switch f.Name {
		case "conf":
			if err := cmd.LoadConfig(&conf, fv, true); err != nil {
				golog.Fatalf("failed loading config: %v", err)
			}
		case "mode":
			if fv == "" {
				fv = "combo"
			}
			m, err := config.ParseMode(fv)
			if err != nil {
				golog.Fatalf("bad mode %q: %v", fv, err)
			}
			conf.Mode = m
		}
	})

	fail := false
	defer func() {
		if fail {
			os.Exit(1)
		}
	}()

	// Grab the warnings to print after the logger is configured.
	ws, err := config.Validate(&conf)
	if err != nil {
		golog.Fatalf("failed to validate config: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := initialize.Logging(ctx, &conf); err != nil {
		golog.Fatalf("failed to set up logging: %v", err)
	}
	ctx = zlog.ContextWithValues(ctx, "component", "main")
	zlog.Info(ctx).
		Str("version", cmd.Version).
		Msg("starting")
	for _, w := range ws {
		zlog.Info(ctx).
			AnErr("lint", &w).Send()
	}
	auto.PrintLogs(ctx)

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
		srv := http.Server{
			BaseContext: func(_ net.Listener) context.Context { return srvctx },
		}
		srv.Handler, err = httptransport.New(srvctx, &conf, srvs.Indexer, srvs.Matcher, srvs.Notifier)
		if err != nil {
			return fmt.Errorf("http transport configuration failed: %w", err)
		}
		l, err := net.Listen("tcp", conf.HTTPListenAddr)
		if err != nil {
			return fmt.Errorf("http transport configuration failed: %w", err)
		}
		if conf.TLS != nil {
			cfg, err := conf.TLS.Config()
			if err != nil {
				return fmt.Errorf("tls configuration failed: %w", err)
			}
			cfg.NextProtos = []string{"h2"}
			srv.TLSConfig = cfg
			l = tls.NewListener(l, cfg)
		}
		down.Add(&srv)
		health.Ready()
		if err := srv.Serve(l); err != http.ErrServerClosed {
			return fmt.Errorf("http transport failed to launch: %w", err)
		}
		return nil
	})

	// Signal handler goroutine.
	go func() {
		ctx, stop := signal.NotifyContext(ctx, os.Interrupt)
		defer func() {
			// Note that we're using a background context here, so that we get a
			// full timeout if the signal handler has fired.
			tctx, done := context.WithTimeout(context.Background(), 10*time.Second)
			err := down.Shutdown(tctx)
			if err != nil {
				zlog.Error(ctx).Err(err).Msg("error shutting down server")
			}
			done()
			stop()
			zlog.Info(ctx).Msg("unregistered signal handler")
		}()
		zlog.Info(ctx).Msg("registered signal handler")
		select {
		case <-ctx.Done():
			zlog.Info(ctx).Stringer("signal", os.Interrupt).Msg("gracefully shutting down")
		case <-srvctx.Done():
		}
	}()

	zlog.Info(ctx).Str("version", cmd.Version).Msg("ready")
	if err := srvs.Wait(); err != nil {
		zlog.Error(ctx).Err(err).Msg("fatal error")
		fail = true
	}
}
