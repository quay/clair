package types

import "github.com/quay/claircore"

// VulnerabilitySummaries is a concrete type for
// https://clairproject.org/api/http/v1/vulnerability_summaries.schema.json.
type VulnerabilitySummaries struct {
	Vulnerabilities []claircore.Vulnerability
}
