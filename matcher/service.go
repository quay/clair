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
	Scan(ctx context.Context, ir *claircore.IndexReport) (*claircore.VulnerabilityReport, error)
}

// Differ is an interface providing information on update operations.
type Differ interface {
	DeleteUpdateOperations(context.Context, ...uuid.UUID) error
	UpdateDiff(_ context.Context, prev, cur uuid.UUID) (*driver.UpdateDiff, error)
	LatestUpdateOperations(context.Context) (map[string]uuid.UUID, error)
	LatestUpdateOperation(context.Context) (uuid.UUID, error)
}
