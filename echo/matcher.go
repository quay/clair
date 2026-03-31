package echo

import (
	"context"

	version "github.com/knqyf263/go-deb-version"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
)

// Matcher is a [driver.Matcher] for Echo distributions.
type Matcher struct{}

var _ driver.Matcher = (*Matcher)(nil)

// Name implements [driver.Matcher].
func (*Matcher) Name() string {
	return "echo-matcher"
}

// Filter implements [driver.Matcher].
func (*Matcher) Filter(record *claircore.IndexRecord) bool {
	if record.Distribution == nil {
		return false
	}
	return record.Distribution.DID == "echo"
}

// Query implements [driver.Matcher].
func (*Matcher) Query() []driver.MatchConstraint {
	return []driver.MatchConstraint{
		driver.DistributionDID,
	}
}

// Vulnerable implements [driver.Matcher].
func (*Matcher) Vulnerable(ctx context.Context, record *claircore.IndexRecord, vuln *claircore.Vulnerability) (bool, error) {
	if vuln.FixedInVersion == "" {
		return true, nil
	}
	// If fixed_version is 0, the package is unaffected.
	if vuln.FixedInVersion == "0" {
		return false, nil
	}

	v1, err := version.NewVersion(record.Package.Version)
	if err != nil {
		return false, err
	}
	v2, err := version.NewVersion(vuln.FixedInVersion)
	if err != nil {
		return false, err
	}

	if v1.LessThan(v2) {
		return true, nil
	}

	return false, nil
}
