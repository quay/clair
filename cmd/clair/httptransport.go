package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"github.com/quay/claircore/libindex"
	"github.com/quay/claircore/libvuln"
	"go.opentelemetry.io/otel/plugin/othttp"

	"github.com/quay/clair/v4/config"
	"github.com/quay/clair/v4/indexer"
	"github.com/quay/clair/v4/matcher"
)

// httptransport configures an http server according to Clair's operation mode.
func httptransport(ctx context.Context, conf config.Config) (*http.Server, error) {
	var srv *http.Server
	var err error
	switch {
	case conf.Mode == config.DevMode:
		srv, err = devMode(ctx, conf)
	case conf.Mode == config.IndexerMode:
		srv, err = indexerMode(ctx, conf)
	case conf.Mode == config.MatcherMode:
		srv, err = matcherMode(ctx, conf)
	default:
		return nil, fmt.Errorf("mode not implemented: %v", conf.Mode)
	}
	if err != nil {
		return nil, err
	}
	if err := setAuth(srv, conf); err != nil {
		return nil, err
	}
	return srv, nil
}

func devMode(ctx context.Context, conf config.Config) (*http.Server, error) {
	libI, err := libindex.New(ctx, &libindex.Opts{
		ConnString:           conf.Indexer.ConnString,
		ScanLockRetry:        time.Duration(conf.Indexer.ScanLockRetry) * time.Second,
		LayerScanConcurrency: conf.Indexer.LayerScanConcurrency,
		Migrations:           conf.Indexer.Migrations,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize libindex: %v", err)
	}
	libV, err := libvuln.New(ctx, &libvuln.Opts{
		MaxConnPool: int32(conf.Matcher.MaxConnPool),
		ConnString:  conf.Matcher.ConnString,
		Migrations:  conf.Matcher.Migrations,
	})

	mux := http.NewServeMux()
	indexer, err := indexer.NewHTTPTransport(libI)
	if err != nil {
		return nil, err
	}
	matcher, err := matcher.NewHTTPTransport(libV, libI)
	if err != nil {
		return nil, err
	}
	indexer.Register(mux)
	matcher.Register(mux)
	return &http.Server{
		Addr:    conf.HTTPListenAddr,
		Handler: othttp.NewHandler(Compress(mux), "server"),
	}, nil
}

func indexerMode(ctx context.Context, conf config.Config) (*http.Server, error) {
	libI, err := libindex.New(ctx, &libindex.Opts{
		ConnString:           conf.Indexer.ConnString,
		ScanLockRetry:        time.Duration(conf.Indexer.ScanLockRetry) * time.Second,
		LayerScanConcurrency: conf.Indexer.LayerScanConcurrency,
		Migrations:           conf.Indexer.Migrations,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize libindex: %v", err)
	}

	indexer, err := indexer.NewHTTPTransport(libI)
	if err != nil {
		return nil, err
	}
	return &http.Server{
		Addr:    conf.Indexer.HTTPListenAddr,
		Handler: othttp.NewHandler(Compress(indexer), "server"),
	}, nil
}

func matcherMode(ctx context.Context, conf config.Config) (*http.Server, error) {
	libV, err := libvuln.New(ctx, &libvuln.Opts{
		MaxConnPool: int32(conf.Matcher.MaxConnPool),
		ConnString:  conf.Matcher.ConnString,
		Migrations:  conf.Matcher.Migrations,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize libvuln: %v", err)
	}
	// matcher mode needs a remote indexer client
	indexer, err := indexer.NewHTTPClient(ctx, conf, nil)
	if err != nil {
		return nil, err
	}
	matcher, err := matcher.NewHTTPTransport(libV, indexer)
	if err != nil {
		return nil, err
	}
	return &http.Server{
		Addr:    conf.Matcher.HTTPListenAddr,
		Handler: othttp.NewHandler(Compress(matcher), "server"),
	}, nil
}

func setAuth(srv *http.Server, conf config.Config) error {
	switch conf.Auth.Name {
	case "keyserver":
		const param = "api"
		api, ok := conf.Auth.Params[param]
		if !ok {
			return fmt.Errorf("missing needed config key: %q", param)
		}
		ks, err := QuayKeyserver(api)
		if err != nil {
			return err
		}
		srv.Handler = AuthHandler(srv.Handler, ks)
	case "psk":
		const (
			iss = "issuer"
			key = "key"
		)
		ek, ok := conf.Auth.Params[key]
		if !ok {
			return fmt.Errorf("missing needed config key: %q", key)
		}
		k, err := base64.StdEncoding.DecodeString(ek)
		if err != nil {
			return err
		}
		i, ok := conf.Auth.Params[iss]
		if !ok {
			return fmt.Errorf("missing needed config key: %q", iss)
		}
		psk, err := PSKAuth(k, i)
		if err != nil {
			return err
		}
		srv.Handler = AuthHandler(srv.Handler, psk)
	case "":
	default:
		return fmt.Errorf("unknown auth kind %q", conf.Auth.Name)
	}
	return nil
}
