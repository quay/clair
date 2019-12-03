package matcher

import (
	"context"
	"fmt"

	clairerror "github.com/quay/clair/v4/clair-error"
	"github.com/quay/clair/v4/config"
	"github.com/quay/clair/v4/indexer"
	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln"
)

// Service provides the interface for converting claircore.IndexReport to claircore.VulnerabilityReport.
//
// Service is also reponsible for updating and keeping our database of vulnerabilities consistent.
//
// Service is transport independent and may be passed into any tranport implementation.
type Service interface {
	Match(ctx context.Context, manifestHash string) (*claircore.VulnerabilityReport, error)
}

// service is a private implementation of a local matcher.Service
type service struct {
	lib     libvuln.Libvuln
	indexer indexer.Service
}

// NewService is a constructor for a new local Service
func NewService(ctx context.Context, conf config.Config, indexer indexer.Service) (Service, error) {
	lib, err := libvuln.New(ctx, &libvuln.Opts{
		ConnString:  conf.Matcher.ConnString,
		MaxConnPool: int32(conf.Matcher.MaxConnPool),
		Run:         conf.Matcher.Run,
		Migrations:  conf.Matcher.Migrations,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create matcher service: %w", err)
	}
	return &service{lib, indexer}, nil
}

// Match looks up the IndexReport for a manifest and computes the VulnerabilityReport
func (s *service) Match(ctx context.Context, manifestHash string) (*claircore.VulnerabilityReport, error) {
	report, err := s.indexer.IndexReport(ctx, manifestHash)
	if err != nil {
		return nil, err
	}

	vr, err := s.lib.Scan(ctx, report)
	if err != nil {
		return nil, &clairerror.ErrMatch{E: err}
	}
	return vr, nil
}
