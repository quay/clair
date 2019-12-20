package main

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/quay/claircore/libindex"
	"github.com/quay/claircore/libvuln"

	"github.com/quay/clair/v4/config"
	"github.com/quay/clair/v4/indexer"
	"github.com/quay/clair/v4/matcher"
)

const (
	HealthApiPath = "/healthz"
)

// httptransport configures an http server according to Clair's operation mode.
func httptransport(ctx context.Context, conf config.Config) (*http.Server, error) {
	switch {
	case conf.Mode == config.DevMode:
		return devMode(ctx, conf)
	case conf.Mode == config.IndexerMode:
		return indexerMode(ctx, conf)
	case conf.Mode == config.MatcherMode:
		return matcherMode(ctx, conf)
	default:
		return nil, fmt.Errorf("mode not implemented: %v", conf.Mode)
	}
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
		Handler: Compress(mux),
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
		Handler: Compress(indexer),
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
		Handler: Compress(matcher),
	}, nil
}
