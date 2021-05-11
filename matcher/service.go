package matcher

import (
	"context"

	"github.com/google/uuid"
	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
)

// Service is an aggregate interface wrapping claircore.Libvuln functionality.
//
// Implementation may use a local instance of claircore.Libindex or a remote
// instance via http or grpc client.
type Service interface {
	Scanner
	Differ
}

// Scanner is an interface providing a claircore.VulnerabilityReport given a claircore.IndexReport
type Scanner interface {
	Initialized(context.Context) (bool, error)
	Scan(ctx context.Context, ir *claircore.IndexReport) (*claircore.VulnerabilityReport, error)
}

// Differ is an interface providing information on update operations.
type Differ interface {
	// DeleteUpdateOperations marks the provided refs as seen and processed.
	DeleteUpdateOperations(context.Context, ...uuid.UUID) (int64, error)
	// UpdateDiff reports the differences between the provided refs.
	//
	// "Prev" can be `uuid.Nil` to indicate "earliest known ref."
	UpdateDiff(_ context.Context, prev, cur uuid.UUID) (*driver.UpdateDiff, error)
	// UpdateOperations returns all the known UpdateOperations per updater.
	UpdateOperations(context.Context, driver.UpdateKind, ...string) (map[string][]driver.UpdateOperation, error)
	// LatestUpdateOperations returns the most recent UpdateOperation per updater.
	LatestUpdateOperations(context.Context, driver.UpdateKind) (map[string][]driver.UpdateOperation, error)
	// LatestUpdateOperation returns a ref for the most recent update operation
	// across all updaters.
	LatestUpdateOperation(context.Context, driver.UpdateKind) (uuid.UUID, error)
}
