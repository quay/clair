package notifier

import "github.com/quay/claircore"

// VulnSummary summarizes a vulnerability which triggered
// a notification
type VulnSummary struct {
	Name           string                  `json:"name"`
	Description    string                  `json:"description"`
	Package        *claircore.Package      `json:"package,omitempty"`
	Distribution   *claircore.Distribution `json:"distribution,omitempty"`
	Repo           *claircore.Repository   `json:"repo,omitempty"`
	Severity       string                  `json:"severity"`
	FixedInVersion string                  `json:"fixed_in_version"`
	Links          string                  `json:"links"`
}

func (vs *VulnSummary) FromVulnerability(v *claircore.Vulnerability) {
	*vs = VulnSummary{
		Name:           v.Name,
		Description:    v.Description,
		Package:        v.Package,
		Distribution:   v.Dist,
		Repo:           v.Repo,
		Severity:       v.NormalizedSeverity.String(),
		FixedInVersion: v.FixedInVersion,
		Links:          v.Links,
	}
}
