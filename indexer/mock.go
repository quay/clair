package indexer

import (
	"context"

	"github.com/quay/claircore"
)

var _ Service = (*Mock)(nil)

// Mock implements a mock indexer Service
//
// If a particular method is not provided an implementation to a constructed Mock
// an "unexpected call" panic will occur.
type Mock struct {
	Index_             func(ctx context.Context, manifest *claircore.Manifest) (*claircore.IndexReport, error)
	IndexReport_       func(ctx context.Context, digest claircore.Digest) (*claircore.IndexReport, bool, error)
	State_             func(ctx context.Context) (string, error)
	AffectedManifests_ func(ctx context.Context, vulns []claircore.Vulnerability) (*claircore.AffectedManifests, error)
	DeleteManifests_   func(context.Context, ...claircore.Digest) ([]claircore.Digest, error)
}

func (i *Mock) Index(ctx context.Context, manifest *claircore.Manifest) (*claircore.IndexReport, error) {
	if i.Index_ == nil {
		panic("mock indexer: unexpected call to Index")
	}
	return i.Index_(ctx, manifest)
}

func (i *Mock) IndexReport(ctx context.Context, digest claircore.Digest) (*claircore.IndexReport, bool, error) {
	if i.IndexReport_ == nil {
		panic("mock indexer: unexpected call to IndexReport")
	}
	return i.IndexReport_(ctx, digest)
}

func (i *Mock) State(ctx context.Context) (string, error) {
	if i.State_ == nil {
		panic("mock indexer: unexpected call to State")
	}
	return i.State_(ctx)
}

func (i *Mock) AffectedManifests(ctx context.Context, vulns []claircore.Vulnerability) (*claircore.AffectedManifests, error) {
	if i.AffectedManifests_ == nil {
		panic("mock indexer: unexpected call to AffectedManifests")
	}
	return i.AffectedManifests_(ctx, vulns)
}

func (i *Mock) DeleteManifests(ctx context.Context, d ...claircore.Digest) ([]claircore.Digest, error) {
	if i.DeleteManifests_ == nil {
		panic("mock indexer: unexpected call to DeleteManifests")
	}
	return i.DeleteManifests_(ctx, d...)
}
