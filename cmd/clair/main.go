package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"time"

	"github.com/quay/clair/config"
	_ "github.com/quay/claircore/updater/defaults"
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
	fail := false
	defer func() {
		if fail {
			os.Exit(1)
		}
	}()
	bail := func(msg string, args ...any) {
		slog.Error(msg, args...)
		fail = true
		runtime.Goexit()
	}

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
			bail("missing flag or environment variable", "flag", "-"+f.Name, "variable", key)
		}
		if fv == "" && ok {
			fv = v
		}
		switch f.Name {
		case "conf":
			if err := cmd.LoadConfig(&conf, fv, true); err != nil {
				bail("failed loading config", "reason", err)
			}
		case "mode":
			if fv == "" {
				fv = "combo"
			}
			m, err := config.ParseMode(fv)
			if err != nil {
				bail("bad mode", "mode", fv, "reason", err)
			}
			conf.Mode = m
		}
	})

	// Grab the warnings to print after the logger is configured.
	ws, err := config.Validate(&conf)
	if err != nil {
		bail("failed to validate config", "reason", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := initialize.Logging(ctx, &conf); err != nil {
		bail("failed to set up logging", "reason", err)
	}
	slog.InfoContext(ctx, "starting", "version", cmd.Version)
	if len(ws) != 0 {
		slog.InfoContext(ctx, "configuration lints",
			"lint", ws)
	}
	auto.PrintLogs(ctx)

	// Signal handler, for orderly shutdown.
	sig, stop := signal.NotifyContext(ctx, append(platformShutdown, os.Interrupt)...)
	defer stop()
	slog.InfoContext(ctx, "registered signal handler")
	go func() {
		<-sig.Done()
		stop()
		slog.InfoContext(ctx, "unregistered signal handler")
	}()

	srvs, srvctx := errgroup.WithContext(sig)
	srvs.Go(serveIntrospection(srvctx, &conf))
	srvs.Go(serveAPI(srvctx, &conf))

	slog.InfoContext(ctx, "ready", "version", cmd.Version)
	if err := srvs.Wait(); err != nil {
		slog.ErrorContext(ctx, "fatal error", "reason", err)
		fail = true
	}
}

func serveAPI(ctx context.Context, cfg *config.Config) func() error {
	return func() error {
		slog.InfoContext(ctx, "launching http transport")
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
		slog.InfoContext(ctx, "launching introspection server")
		srv, err := introspection.New(ctx, cfg, nil)
		if err != nil {
			slog.WarnContext(ctx, "introspection server configuration failed; continuing anyway",
				"reason", err)
			return nil
		}

		var eg errgroup.Group
		eg.Go(func() error {
			if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
				slog.WarnContext(ctx, "introspection server failed to launch; continuing anyway",
					"reason", err)
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
