package echo

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"runtime/trace"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
	"github.com/quay/claircore/osrelease"
)

var (
	_ indexer.DistributionScanner = (*DistributionScanner)(nil)
	_ indexer.VersionedScanner    = (*DistributionScanner)(nil)
)

// DistributionScanner attempts to discover if a layer
// displays characteristics of an Echo distribution.
type DistributionScanner struct{}

// Name implements [indexer.VersionedScanner].
func (*DistributionScanner) Name() string { return "echo" }

// Version implements [indexer.VersionedScanner].
func (*DistributionScanner) Version() string { return "1" }

// Kind implements [indexer.VersionedScanner].
func (*DistributionScanner) Kind() string { return "distribution" }

// Scan implements [indexer.DistributionScanner].
func (ds *DistributionScanner) Scan(ctx context.Context, l *claircore.Layer) ([]*claircore.Distribution, error) {
	defer trace.StartRegion(ctx, "Scanner.Scan").End()
	log := slog.With("version", ds.Version(), "layer", l.Hash.String())
	log.DebugContext(ctx, "start")
	defer log.DebugContext(ctx, "done")

	sys, err := l.FS()
	if err != nil {
		return nil, fmt.Errorf("echo: unable to open layer: %w", err)
	}
	d, err := findDist(ctx, log, sys)
	if err != nil {
		return nil, err
	}
	if d == nil {
		return nil, nil
	}
	return []*claircore.Distribution{d}, nil
}

func findDist(ctx context.Context, log *slog.Logger, sys fs.FS) (*claircore.Distribution, error) {
	f, err := sys.Open(osrelease.Path)
	switch {
	case errors.Is(err, nil):
	case errors.Is(err, fs.ErrNotExist):
		log.DebugContext(ctx, "no os-release file")
		return nil, nil
	default:
		return nil, fmt.Errorf("echo: unexpected error: %w", err)
	}
	kv, err := osrelease.Parse(ctx, f)
	if err != nil {
		log.InfoContext(ctx, "malformed os-release file", "reason", err)
		return nil, nil
	}
	if kv[`ID`] != `echo` {
		return nil, nil
	}

	ver := kv[`VERSION_ID`]
	if ver == "" {
		log.InfoContext(ctx, "echo os-release missing VERSION_ID")
		return nil, nil
	}
	return mkDist(ver), nil
}
