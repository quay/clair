package feature

import "os"

// GraphQL is true if the relevant feature flag was set in the environment.
var GraphQL bool

func init() {
	_, GraphQL = os.LookupEnv(GraphQLFlag)
}
