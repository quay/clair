package indexer

import (
	"context"
	"fmt"
	"time"

	clairerror "github.com/quay/clair/v4/clair-error"
	"github.com/quay/clair/v4/config"
	"github.com/quay/claircore"
	"github.com/quay/claircore/libindex"
)

// Service provides the interface for indexing manifests
//
// Service is transport independent and may be passed into any
// tranport implementation.
type Service interface {
	Index(ctx context.Context, manifest *claircore.Manifest) (*claircore.IndexReport, error)
	IndexReport(ctx context.Context, manifestHash string) (*claircore.IndexReport, error)
}

// service implements a local service implemented via the libindex api
type service struct {
	lib libindex.Libindex
}

// NewService is a constructor for a Service
func NewService(ctx context.Context, conf config.Config) (Service, error) {
	lib, err := libindex.New(ctx, &libindex.Opts{
		ConnString:           conf.Indexer.ConnString,
		ScanLockRetry:        time.Duration(conf.Indexer.ScanLockRetry) * time.Second,
		LayerScanConcurrency: conf.Indexer.LayerScanConcurrency,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create indexer service: %w", err)
	}
	return &service{lib}, nil
}

// Index receives a Manifest and returns a IndexReport providing the indexed
// items in the resulting image.
//
// Index blocks until completion. An error is returned if the index operation
// could not start. If an error occurs during the index operation the error will
// be preset on the IndexReport.Err field of the returned IndexReport.
func (s *service) Index(ctx context.Context, manifest *claircore.Manifest) (*claircore.IndexReport, error) {
	// ToDo: manifest structure validation

	resC, err := s.lib.Index(ctx, manifest)
	if err != nil {
		return nil, &clairerror.ErrIndexStart{err}
	}

	// block until completion
	scanReport := <-resC

	return scanReport, nil
}

// IndexReport retrieves a IndexReport given a manifest hash string
func (s *service) IndexReport(ctx context.Context, manifestHash string) (*claircore.IndexReport, error) {
	report, ok, err := s.lib.IndexReport(ctx, manifestHash)
	if err != nil {
		return nil, &clairerror.ErrIndexReportRetrieval{err}
	}
	if !ok {
		return nil, &clairerror.ErrIndexReportNotFound{manifestHash}
	}
	return report, nil
}
