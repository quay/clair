package main

import (
	"context"
	"flag"
	golog "log"
	"os"
	"os/signal"
	"time"

	"github.com/rs/zerolog"
	yaml "gopkg.in/yaml.v2"

	"github.com/quay/clair/v4/config"
	initialize "github.com/quay/clair/v4/init"
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

	// initialize
	init, err := initialize.New(conf)
	if err != nil {
		golog.Fatalf("failed to initialize Clair: %v", err)
	}
	log := zerolog.Ctx(init.GlobalCTX).With().Str("component", "main").Logger()

	// launch transport
	log.Info().Msgf("launching http transport on %v", init.HttpTransport.Addr)
	go func() {
		err := init.HttpTransport.ListenAndServe()
		if err != nil {
			log.Err(err).Err(err).Msg("http transport failed to servce. canceling global context")
			init.GlobalCancel()
		}
	}()

	// register signal handler
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	log.Info().Msg("registered signal handler for os.Interrupt")

	// block
	select {
	case sig := <-c:
		// received a SIGINT for graceful shutdown
		log.Info().Str("component", "clair-main").Msgf("received signal %v... gracefully shutting down. 10 second timeout", sig)
		tctx, cancel := context.WithTimeout(init.GlobalCTX, 10*time.Second)
		defer cancel()
		init.HttpTransport.Shutdown(tctx)
		os.Exit(0)
	case <-init.GlobalCTX.Done():
		// main cancel func called indicating error initializing
		log.Fatal().Msgf("initialization of clair failed. view log entries for details")
	}
}
