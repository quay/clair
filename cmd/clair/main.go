package main

import (
	"context"
	"crypto/tls"
	"errors"
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

	// Signal handler, for orderly shutdown.
	sig, stop := signal.NotifyContext(ctx, append(platformShutdown, os.Interrupt)...)
	defer stop()
	zlog.Info(ctx).Msg("registered signal handler")
	go func() {
		<-sig.Done()
		stop()
		zlog.Info(ctx).Msg("unregistered signal handler")
	}()

	srvs, srvctx := errgroup.WithContext(sig)
	srvs.Go(serveIntrospection(srvctx, &conf))
	srvs.Go(serveAPI(srvctx, &conf))

	zlog.Info(ctx).
		Str("version", cmd.Version).
		Msg("ready")
	if err := srvs.Wait(); err != nil {
		zlog.Error(ctx).
			Err(err).
			Msg("fatal error")
		fail = true
	}
}

func serveAPI(ctx context.Context, cfg *config.Config) func() error {
	return func() error {
		zlog.Info(ctx).Msg("launching http transport")
		srvs, err := initialize.Services(ctx, cfg)
		if err != nil {
			return fmt.Errorf("service initialization failed: %w", err)
		}
		srv := http.Server{
			BaseContext: func(_ net.Listener) context.Context {
				return context.WithoutCancel(ctx)
			},
		}
		srv.Handler, err = httptransport.New(ctx, cfg, srvs.Indexer, srvs.Matcher, srvs.Notifier)
		if err != nil {
			return fmt.Errorf("http transport configuration failed: %w", err)
		}
		l, err := net.Listen("tcp", cfg.HTTPListenAddr)
		if err != nil {
			return fmt.Errorf("http transport configuration failed: %w", err)
		}
		if cfg.TLS != nil {
			cfg, err := cfg.TLS.Config()
			if err != nil {
				return fmt.Errorf("tls configuration failed: %w", err)
			}
			cfg.NextProtos = []string{"h2"}
			srv.TLSConfig = cfg
			l = tls.NewListener(l, cfg)
		}
		health.Ready()

		var eg errgroup.Group
		eg.Go(func() error {
			if err := srv.Serve(l); !errors.Is(err, http.ErrServerClosed) {
				return fmt.Errorf("http transport failed to launch: %w", err)
			}
			return nil
		})
		eg.Go(func() error {
			<-ctx.Done()
			ctx, done := context.WithTimeoutCause(context.Background(), 10*time.Second, context.Cause(ctx))
			defer done()
			return srv.Shutdown(ctx)
		})
		return eg.Wait()
	}
}

func serveIntrospection(ctx context.Context, cfg *config.Config) func() error {
	return func() error {
		zlog.Info(ctx).Msg("launching introspection server")
		srv, err := introspection.New(ctx, cfg, nil)
		if err != nil {
			zlog.Warn(ctx).
				Err(err).
				Msg("introspection server configuration failed; continuing anyway")
			return nil
		}

		var eg errgroup.Group
		eg.Go(func() error {
			if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
				zlog.Warn(ctx).
					Err(err).
					Msg("introspection server failed to launch; continuing anyway")
			}
			return nil
		})
		eg.Go(func() error {
			<-ctx.Done()
			ctx, done := context.WithTimeoutCause(context.Background(), 10*time.Second, context.Cause(ctx))
			defer done()
			return srv.Shutdown(ctx)
		})
		return eg.Wait()
	}
}
