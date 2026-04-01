package echo

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"

	"github.com/quay/claircore"
)

// advisoryData maps source package name to its vulnerabilities.
type advisoryData map[string]map[string]cveEntry

// cveEntry holds vulnerability data for a single CVE.
type cveEntry struct {
	FixedVersion string `json:"fixed_version"`
}

// Parse implements [driver.Parser].
func (u *echoUpdater) Parse(ctx context.Context, r io.ReadCloser) ([]*claircore.Vulnerability, error) {
	slog.InfoContext(ctx, "starting parse")
	defer r.Close()

	var data advisoryData
	if err := json.NewDecoder(r).Decode(&data); err != nil {
		return nil, fmt.Errorf("echo: unable to parse advisory JSON: %w", err)
	}

	dist := getDist()

	var vs []*claircore.Vulnerability
	for pkg, cves := range data {
		for cveID, entry := range cves {
			v := &claircore.Vulnerability{
				Updater:        u.Name(),
				Name:           cveID,
				Links:          linkPrefix + cveID,
				Dist:           dist,
				FixedInVersion: entry.FixedVersion,
				Package: &claircore.Package{
					Name: pkg,
					Kind: claircore.SOURCE,
				},
			}
			vs = append(vs, v)
		}
	}

	slog.InfoContext(ctx, "parsed advisory database", "vulnerabilities", len(vs))
	return vs, nil
}
