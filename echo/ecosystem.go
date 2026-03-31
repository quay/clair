package echo

import (
	"context"

	"github.com/quay/claircore/debian"
	"github.com/quay/claircore/dpkg"
	"github.com/quay/claircore/indexer"
	"github.com/quay/claircore/linux"
	"github.com/quay/claircore/ubuntu"
)

// NewDpkgEcosystem provides the set of scanners and coalescers for the dpkg
// ecosystem, extended to include the Echo distribution scanner alongside the
// Debian and Ubuntu scanners.
func NewDpkgEcosystem(ctx context.Context) *indexer.Ecosystem {
	return &indexer.Ecosystem{
		PackageScanners: func(ctx context.Context) ([]indexer.PackageScanner, error) {
			return []indexer.PackageScanner{
				&dpkg.Scanner{},
				&dpkg.DistrolessScanner{},
			}, nil
		},
		DistributionScanners: func(ctx context.Context) ([]indexer.DistributionScanner, error) {
			return []indexer.DistributionScanner{
				&debian.DistributionScanner{},
				&ubuntu.DistributionScanner{},
				&DistributionScanner{},
			}, nil
		},
		RepositoryScanners: func(ctx context.Context) ([]indexer.RepositoryScanner, error) {
			return []indexer.RepositoryScanner{}, nil
		},
		Coalescer: func(ctx context.Context) (indexer.Coalescer, error) {
			return linux.NewCoalescer(), nil
		},
	}
}
