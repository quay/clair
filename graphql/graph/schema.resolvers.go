package graph

// This file will be automatically regenerated based on the schema, any resolver implementations
// will be copied through when generating and any unknown code will be moved to the end.

import (
	"context"
	"fmt"

	"github.com/quay/clair/v4/graphql/graph/generated"
	"github.com/quay/clair/v4/graphql/graph/model"
	"github.com/quay/claircore"
)

func (r *queryResolver) Report(ctx context.Context, digest claircore.Digest) (*model.ReportResponse, error) {
	ir, _, err := r.Indexer.IndexReport(ctx, digest)
	if err != nil {
		return nil, err
	}
	vr, err := r.Matcher.Scan(ctx, ir)
	if err != nil {
		return nil, err
	}

	var ret model.ReportResponse
	ret.Packages = make([]model.PackageReport, len(vr.Packages))
	ret.Enrichments = make([]model.Enrichment, len(vr.Enrichments))

	i := 0
	for id, pkg := range vr.Packages {
		pr := &ret.Packages[i]
		pr.ID = pkg.ID
		// Populate the package.

		// Populate the vulnerabilities
		pr.Vulnerability = make([]model.Vulnerability, len(vr.PackageVulnerabilities[id]))
		for i, id := range vr.PackageVulnerabilities[id] {
			pr.Vulnerability[i].ID = id
		}

		// Grab the last environment. This format needs some rethinking.
		es := vr.Environments[id]
		env := es[len(es)-1]

		// Populate distribution.
		d := vr.Distributions[env.DistributionID]
		pr.Distribution.ID = d.ID

		// Populate repositories.
		pr.Repository = make([]model.Repository, len(env.RepositoryIDs))
		for i, id := range env.RepositoryIDs {
			r := vr.Repositories[id]
			rr := &pr.Repository[i]
			rr.ID = r.ID
		}

		i++
	}

	i = 0
	for kind, es := range vr.Enrichments {
		e := &ret.Enrichments[i]
		e.Type = kind
		e.Enrichment = es
		i++
	}

	return &ret, nil
}

// Query returns generated.QueryResolver implementation.
func (r *Resolver) Query() generated.QueryResolver { return &queryResolver{r} }

type queryResolver struct{ *Resolver }

// !!! WARNING !!!
// The code below was going to be deleted when updating resolvers. It has been copied here so you have
// one last chance to move it out of harms way if you want. There are two reasons this happens:
//  - When renaming or deleting a resolver the old code will be put in here. You can safely delete
//    it when you're done.
//  - You have helper methods in this file. Move them out to keep these resolver files clean.
func (r *queryResolver) Vulnerabilities(ctx context.Context, digest claircore.Digest) ([]model.Vulnerability, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *queryResolver) VulnerabilityReport(ctx context.Context, digest claircore.Digest) (*model.VulnerabilityReport, error) {
	panic(fmt.Errorf("not implemented"))
}
