package matcher

import (
	"context"

	"github.com/quay/claircore"
)

// Service creates an interface around claircore.Libvuln
type Service interface {
	// Scan(ctx context.Context, manifestHash string) (*claircore.VulnerabilityReport, error)
	Scan(ctx context.Context, ir *claircore.IndexReport) (*claircore.VulnerabilityReport, error)
}
