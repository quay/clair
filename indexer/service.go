package indexer

import (
	"context"

	"github.com/quay/clair/v4/config"
	"github.com/quay/claircore"
	"github.com/quay/claircore/libscan"
)

// Service provides the interface for indexing manifests
//
// A Service is transport independent and may be passed into any
// tranport implementation.
type Service struct {
	lib libscan.Libscan
}

// NewService is a constructor for a Service
func NewService(conf config.Config) (*Service, error) {
	opts := libscan.Op
}

// Index receives a Manifest and returns a ScanReport providing the indexed
// items in the resulting image.
//
// Index blocks until completion. An error is returned if the index operation
// could not start. If an error occurs during the index operation the error will
// be preset on the ScanReport.Err field of the returned ScanReport.
func (s *Service) Index(ctx context.Context, manifest *claircore.Manifest) (*claircore.ScanReport, error) {
	// ToDo: manifest structure validation

	resC, err := s.lib.Scan(ctx, manifest)
	if err != nil {
		return nil, &ErrIndexStart{err}
	}

	// block until completion
	scanReport := <-resC

	return scanReport, nil
}

func (s *Service) IndexReport(ctx context.Context, manifestHash string) (*claircore.ScanReport, error) {
	report, ok, err := s.lib.ScanReport(ctx, manifestHash)
	if err != nil {
		return nil, &ErrIndexReportRetrieval{err}
	}
	if !ok {
		return nil, &ErrIndexReportNotFound{manifestHash}
	}
	return report, nil
}
