package main

import (
	"context"
	"fmt"
	"net/http"

	"github.com/quay/clair/v4/config"
	"github.com/quay/clair/v4/indexer"
	"github.com/quay/clair/v4/matcher"
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
	mux := http.NewServeMux()
	indexerServ, err := indexer.NewService(ctx, conf)
	if err != nil {
		return nil, err
	}
	matcherServ, err := matcher.NewService(ctx, conf, indexerServ)
	if err != nil {
		return nil, err
	}
	mux.HandleFunc(indexer.IndexAPIPath, indexer.IndexHandler(indexerServ))
	mux.HandleFunc(indexer.IndexReportAPIPath, indexer.IndexReportHandler(indexerServ))
	mux.HandleFunc(matcher.VulnerabilityReportAPIPath, matcher.MatchHandler(matcherServ))
	return &http.Server{
		Addr:    conf.HTTPListenAddr,
		Handler: mux,
	}, nil
}

func indexerMode(ctx context.Context, conf config.Config) (*http.Server, error) {
	mux := http.NewServeMux()
	indexerServ, err := indexer.NewService(ctx, conf)
	if err != nil {
		return nil, err
	}
	mux.HandleFunc(indexer.IndexAPIPath, indexer.IndexHandler(indexerServ))
	mux.HandleFunc(indexer.IndexReportAPIPath, indexer.IndexReportHandler(indexerServ))
	return &http.Server{
		Addr:    conf.Indexer.HTTPListenAddr,
		Handler: mux,
	}, nil
}

func matcherMode(ctx context.Context, conf config.Config) (*http.Server, error) {
	mux := http.NewServeMux()
	// matcher mode needs a remote indexer client
	indexerServ, err := indexer.NewHTTPClient(ctx, conf, nil)
	if err != nil {
		return nil, err
	}
	matcherServ, err := matcher.NewService(ctx, conf, indexerServ)
	if err != nil {
		return nil, err
	}
	mux.HandleFunc(indexer.IndexAPIPath, indexer.IndexHandler(indexerServ))
	mux.HandleFunc(indexer.IndexReportAPIPath, indexer.IndexReportHandler(indexerServ))
	mux.HandleFunc(matcher.VulnerabilityReportAPIPath, matcher.MatchHandler(matcherServ))
	return &http.Server{
		Addr:    conf.Matcher.HTTPListenAddr,
		Handler: mux,
	}, nil

}
