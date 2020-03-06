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
	yaml "gopkg.in/yaml.v2"

	"github.com/quay/clair/v4/config"
)

// Version is a version string, optionally injected at build time.
var Version string

const (
	envConfig = `CLAIR_CONF`
	envMode   = `CLAIR_MODE`
)

func main() {
	// parse conf cli
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
	err = config.Validate(conf)
	if err != nil {
		golog.Fatalf("failed to validate config: %v", err)
	}

	// setup global log level
	var out io.Writer = os.Stderr
	ll := logLevel(&conf)
	if ll == zerolog.DebugLevel {
		out = zerolog.ConsoleWriter{
			Out: os.Stderr,
		}
	}
	log := zerolog.New(out).With().
		Timestamp().
		Logger().
		Level(ll)

	// create global application context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// derive ctx with logger attached. we will propagate a logger via context to all long living components
	ctx = log.WithContext(ctx)
	logger := log.With().
		Str("component", "cmd/clair/main").
		Logger()
	logfunc := func(_ net.Listener) context.Context {
		return ctx
	}
	log.Info().
		Str("mode", runMode.String()).
		Str("config", confFile.String()).
		Msg("start")

	// Make sure to configure our metrics and tracing providers before creating
	// any package objects that may close over a provider.
	//
	// This is structured in a non-idiomatic way because we don't want a failure
	// to stop the program.
	intro, err := introspection(ctx, &conf, func() bool { return true })
	if err != nil {
		logger.Error().Err(err).Msg("failed to create introspection server")
	} else {
		intro.BaseContext = logfunc
		addr := conf.IntrospectionAddr
		if addr == "" {
			addr = ":0"
		}
		l, err := net.Listen("tcp", addr)
		if err != nil {
			l.Close()
			logger.Error().Err(err).Msg("failed to create introspection server")
		} else {
			logger.Info().
				Str("addr", l.Addr().String()).
				Msgf("launching introspection via http")
			// The Serve method closes the net.Listener.
			go func() {
				if err := intro.Serve(l); err != nil && err != http.ErrServerClosed {
					logger.Error().Err(err).Msg("launching introspection via http failed")
				}
				defer intro.Shutdown(ctx)
			}()
		}
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

	up := logger.Info()
	if Version != "" {
		up = up.Str("version", Version)
	}
	up.Msg("ready")
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

func logLevel(conf *config.Config) zerolog.Level {
	level := strings.ToLower(conf.LogLevel)
	switch level {
	case "debug":
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
