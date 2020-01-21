package main

import (
	"context"
	"flag"
	golog "log"
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
	level := logLevel(conf)
	zerolog.SetGlobalLevel(level)

	// create global application context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// derive ctx with logger attached. we will propagate a logger via context to all long living components
	logger := log.With().Str("version", Version).Logger()
	lctx := logger.WithContext(ctx)

	// return a http server with the correct handlers given the config's Mode attribute.
	server, err := httptransport(lctx, conf)
	if err != nil {
		logger.Fatal().Msgf("failed to create http transport: %v", err)
	}
	logger.Info().Str("component", "clair-main").Msgf("launching http transport on %v", server.Addr)
	go func() {
		err := server.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			logger.Error().Str("component", "clair-main").Msgf("launching http transport failed %v", err)
			cancel()
		}
	}()

	// register signal handler
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	// block
	select {
	case sig := <-c:
		// received a SIGINT for graceful shutdown
		logger.Info().Str("component", "clair-main").Msgf("received signal %v... gracefully shutting down. 10 second timeout", sig)
		tctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		server.Shutdown(tctx)
		os.Exit(0)
	case <-ctx.Done():
		// main cancel func called indicating error initializing
		logger.Fatal().Msgf("initialization of clair failed. view log entries for details")
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
