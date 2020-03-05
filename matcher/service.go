package matcher

import (
	"context"

	"github.com/quay/claircore"
)

// Service is an aggregate interface wrapping claircore.Libvuln functionality.
//
// Implementation may use a local instance of claircore.Libindex or a remote
// instance via http or grpc client.
type Service interface {
	Scanner
}

// Scanner is an interface providing a claircore.VulnerabilityReport given a claircore.IndexReport
type Scanner interface {
	Scan(ctx context.Context, ir *claircore.IndexReport) (*claircore.VulnerabilityReport, error)
}
