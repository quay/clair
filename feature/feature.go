// Package feature implements feature flags for all the packages in the clair
// module.
//
// Any features referenced here should be considered experimental: that is,
// there's no guarantee around APIs, configuration, usability, forward
// compatibility, backwards compatibility, stability, etc.
package feature

// Environment variables currently examined for feature flags.
//
// These are subject to removal, addition, or reinterpretation at any time.
const (
	// GraphQLFlag being set in the environment toggles on registering a
	// GraphQL endpoint at "/matcher/api/v1/graphql".
	GraphQLFlag = `CLAIR_FEATURE_GRAPHQL`
)
