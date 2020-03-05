package main

import (
	"context"
	"flag"
	"io"
	golog "log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	yaml "gopkg.in/yaml.v2"

	"github.com/quay/clair/v4/config"
)

const (
	Version = "v4.0.0-rc01"
)

func main() {
	// parse conf cli
	var confv ConfValue
	flag.Var(&confv, "conf", "The file system path to Clair's config file.")
	flag.Parse()
	if confv.String() == "" {
		golog.Fatalf("must provide a -conf flag")
	}

	// validate config
	var conf config.Config
	err := yaml.NewDecoder(confv.file).Decode(&conf)
	if err != nil {
		golog.Fatalf("failed to decode yaml config: %v", err)
	}
	err = config.Validate(conf)
	if err != nil {
		golog.Fatalf("failed to validate config: %v", err)
	}

	// setup global log level
	var out io.Writer = os.Stderr
	if conf.Mode == config.DevMode {
		out = zerolog.ConsoleWriter{
			Out: os.Stderr,
		}
	}
	log := zerolog.New(out).With().
		Timestamp().
		Logger().
		Level(logLevel(conf))

	// create global application context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// derive ctx with logger attached. we will propagate a logger via context to all long living components
	ctx = log.WithContext(ctx)
	logger := log.With().
		Str("component", "cmd/clair/main").
		Str("version", Version).
		Logger()
	logfunc := func(_ net.Listener) context.Context {
		return ctx
	}

	// Make sure to configure our metrics and tracing providers before creating
	// any package objects that may close over a provider.
	intro, err := introspection(ctx, &conf, func() bool { return true })
	if err != nil {
		logger.Error().Err(err).Msg("failed to create introspection server")
	} else {
		intro.BaseContext = logfunc
		logger.Info().
			Str("addr", intro.Addr).
			Msgf("launching introspection via http")
		go func() {
			if err := intro.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logger.Error().Err(err).Msg("launching introspection via http failed")
			}
			defer intro.Shutdown(ctx)
		}()
	}

	// return a http server with the correct handlers given the config's Mode attribute.
	server, err := httptransport(ctx, conf)
	if err != nil {
		logger.Fatal().
			Err(err).
			Msgf("failed to create api server")
	}
	server.BaseContext = logfunc
	logger.Info().
		Str("addr", server.Addr).
		Msgf("launching api via http")
	go func() {
		err := server.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			logger.Error().
				Err(err).
				Msg("launching api via http failed")
			cancel()
		}
	}()

	// register signal handler
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	logger.Info().Msg("🆙")
	// block
	select {
	case sig := <-c:
		// received a SIGINT for graceful shutdown
		logger.Info().
			Str("signal", sig.String()).
			Msg("gracefully shutting down")
		tctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		server.Shutdown(tctx)
	case <-ctx.Done():
		// main cancel func called indicating error initializing
		logger.Fatal().Msg("initialization failed")
	}
}

func logLevel(conf config.Config) zerolog.Level {
	level := strings.ToLower(conf.LogLevel)
	switch level {
	case "debug":
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
		return zerolog.DebugLevel
	case "info":
		return zerolog.InfoLevel
	case "warn":
		return zerolog.WarnLevel
	case "error":
		return zerolog.ErrorLevel
	case "fatal":
		return zerolog.FatalLevel
	case "panic":
		return zerolog.PanicLevel
	default:
		return zerolog.InfoLevel
	}
}
