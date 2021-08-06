package graph

import (
	"github.com/quay/clair/v4/indexer"
	"github.com/quay/clair/v4/matcher"
)

type Resolver struct {
	// TODO Maybe it makes sense to declare a storage API in claircore?

	Indexer indexer.Reporter
	Matcher matcher.Scanner
}
