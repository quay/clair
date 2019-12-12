package indexer

import (
	"context"

	"github.com/quay/claircore"
)

// Service creates an interface around claircore.Libindex
type Service interface {
	Index(ctx context.Context, manifest *claircore.Manifest) (*claircore.IndexReport, error)
	IndexReport(ctx context.Context, manifestHash string) (*claircore.IndexReport, bool, error)
	State() string
}
