package httptransport

import (
	"context"

	"github.com/google/uuid"
	"github.com/quay/clair/v4/indexer"
	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
)

var _ indexer.Service = (*indexerMock)(nil)

type indexerMock struct {
	index    func(ctx context.Context, manifest *claircore.Manifest) (*claircore.IndexReport, error)
	report   func(ctx context.Context, digest claircore.Digest) (*claircore.IndexReport, bool, error)
	state    func(ctx context.Context) (string, error)
	affected func(ctx context.Context, vulns []claircore.Vulnerability) (claircore.AffectedManifests, error)
}

func (i *indexerMock) Index(ctx context.Context, manifest *claircore.Manifest) (*claircore.IndexReport, error) {
	return i.index(ctx, manifest)
}

func (i *indexerMock) IndexReport(ctx context.Context, digest claircore.Digest) (*claircore.IndexReport, bool, error) {
	return i.report(ctx, digest)
}

func (i *indexerMock) State(ctx context.Context) (string, error) {
	return i.state(ctx)
}

func (i *indexerMock) AffectedManifests(ctx context.Context, vulns []claircore.Vulnerability) (claircore.AffectedManifests, error) {
	return i.affected(ctx, vulns)
}

// scanner implements the matcher.Scanner interface
type scanner struct {
	scan func(context.Context, *claircore.IndexReport) (*claircore.VulnerabilityReport, error)
}

func (s *scanner) Scan(ctx context.Context, ir *claircore.IndexReport) (*claircore.VulnerabilityReport, error) {
	return s.scan(ctx, ir)
}

// Differ implements matcher.Differ by calling the func members.
type differ struct {
	delete     func(context.Context, ...uuid.UUID) error
	ops        func(context.Context, ...string) (map[string][]driver.UpdateOperation, error)
	latestOp   func(context.Context) (uuid.UUID, error)
	latestOps  func(context.Context) (map[string][]driver.UpdateOperation, error)
	updateDiff func(context.Context, uuid.UUID, uuid.UUID) (*driver.UpdateDiff, error)
}

// DeleteUpdateOperations marks the provided refs as seen and processed.
func (d *differ) DeleteUpdateOperations(ctx context.Context, refs ...uuid.UUID) error {
	return d.delete(ctx, refs...)
}

// UpdateDiff reports the differences between the provided refs.
//
// "Prev" can be `uuid.Nil` to indicate "earliest known ref."
func (d *differ) UpdateDiff(ctx context.Context, prev uuid.UUID, cur uuid.UUID) (*driver.UpdateDiff, error) {
	return d.updateDiff(ctx, prev, cur)
}

// UpdateOperations returns all the known UpdateOperations per updater.
func (d *differ) UpdateOperations(ctx context.Context, updaters ...string) (map[string][]driver.UpdateOperation, error) {
	return d.ops(ctx, updaters...)
}

// LatestUpdateOperations returns the most recent UpdateOperation per updater.
func (d *differ) LatestUpdateOperations(ctx context.Context) (map[string][]driver.UpdateOperation, error) {
	return d.latestOps(ctx)
}

// LatestUpdateOperation returns a ref for the most recent update operation
// across all updaters.
func (d *differ) LatestUpdateOperation(ctx context.Context) (uuid.UUID, error) {
	return d.latestOp(ctx)
}
