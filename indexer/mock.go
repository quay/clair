package indexer

import (
	"context"

	"github.com/quay/claircore"
)

var _ Service = (*Mock)(nil)

// Mock implements a mock indexer Service
type Mock struct {
	Index_             func(ctx context.Context, manifest *claircore.Manifest) (*claircore.IndexReport, error)
	IndexReport_       func(ctx context.Context, digest claircore.Digest) (*claircore.IndexReport, bool, error)
	State_             func(ctx context.Context) (string, error)
	AffectedManifests_ func(ctx context.Context, vulns []claircore.Vulnerability) (claircore.AffectedManifests, error)
}

func (i *Mock) Index(ctx context.Context, manifest *claircore.Manifest) (*claircore.IndexReport, error) {
	return i.Index_(ctx, manifest)
}

func (i *Mock) IndexReport(ctx context.Context, digest claircore.Digest) (*claircore.IndexReport, bool, error) {
	return i.IndexReport_(ctx, digest)
}

func (i *Mock) State(ctx context.Context) (string, error) {
	return i.State_(ctx)
}

func (i *Mock) AffectedManifests(ctx context.Context, vulns []claircore.Vulnerability) (claircore.AffectedManifests, error) {
	return i.AffectedManifests_(ctx, vulns)
}
