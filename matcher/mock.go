package matcher

import (
	"context"
	"sync"

	"github.com/google/uuid"
	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
)

var _ Service = (*Mock)(nil)

// Mock implements a mock matcher service
type Mock struct {
	DeleteUpdateOperations_ func(context.Context, ...uuid.UUID) error
	UpdateOperations_       func(context.Context, ...string) (map[string][]driver.UpdateOperation, error)
	LatestUpdateOperation_  func(context.Context) (uuid.UUID, error)
	LatestUpdateOperations_ func(context.Context) (map[string][]driver.UpdateOperation, error)
	UpdateDiff_             func(context.Context, uuid.UUID, uuid.UUID) (*driver.UpdateDiff, error)
	Scan_                   func(context.Context, *claircore.IndexReport) (*claircore.VulnerabilityReport, error)
	// TestUOs provide memory for the mock.
	// usage of this field can be dictated by the test case's needs.
	sync.Mutex
	TestUOs map[string][]driver.UpdateOperation
}

// DeleteUpdateOperations marks the provided refs as seen and processed.
func (d *Mock) DeleteUpdateOperations(ctx context.Context, refs ...uuid.UUID) error {
	return d.DeleteUpdateOperations_(ctx, refs...)
}

// UpdateDiff reports the differences between the provided refs.
//
// "Prev" can be `uuid.Nil` to indicate "earliest known ref."
func (d *Mock) UpdateDiff(ctx context.Context, prev uuid.UUID, cur uuid.UUID) (*driver.UpdateDiff, error) {
	return d.UpdateDiff_(ctx, prev, cur)
}

// UpdateOperations returns all the known UpdateOperations per updater.
func (d *Mock) UpdateOperations(ctx context.Context, updaters ...string) (map[string][]driver.UpdateOperation, error) {
	return d.UpdateOperations_(ctx, updaters...)
}

// LatestUpdateOperations returns the most recent UpdateOperation per updater.
func (d *Mock) LatestUpdateOperations(ctx context.Context) (map[string][]driver.UpdateOperation, error) {
	return d.LatestUpdateOperations_(ctx)
}

// LatestUpdateOperation returns a ref for the most recent update operation
// across all updaters.
func (d *Mock) LatestUpdateOperation(ctx context.Context) (uuid.UUID, error) {
	return d.LatestUpdateOperation_(ctx)
}

func (s *Mock) Scan(ctx context.Context, ir *claircore.IndexReport) (*claircore.VulnerabilityReport, error) {
	return s.Scan_(ctx, ir)
}
