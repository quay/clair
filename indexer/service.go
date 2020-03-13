package indexer

import (
	"context"

	"github.com/quay/claircore"
)

// Service is an aggregate interface wrapping claircore.Libindex functionality.
//
// Implementation may use a local instance of claircore.Libindex or a remote
// instance via http or grpc client.
type Service interface {
	Indexer
	Reporter
	Stater
}

// StateReporter is an aggregate interface providing both a Reporter and
// a Stater method set
type StateReporter interface {
	Reporter
	Stater
}

// StateIndexer is an aggregate interface providing both a Indexer
// and a Stater method set
type StateIndexer interface {
	Indexer
	Stater
}

// Indexer is an interface providing a claircore.IndexReport given a claircore.Manifest
type Indexer interface {
	Index(ctx context.Context, manifest *claircore.Manifest) (*claircore.IndexReport, error)
}

// Reporter is an interface providing a claircore.IndexReport provided a claircore.Digest which represents a manifest hash.
type Reporter interface {
	IndexReport(ctx context.Context, digest claircore.Digest) (*claircore.IndexReport, bool, error)
}

// Stater is an interface which provides a unique token symbolizing a Clair's state.
type Stater interface {
	State(ctx context.Context) (string, error)
}
