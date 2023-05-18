package config

// Matchers configures the individual matchers run by the matcher system.
type Matchers struct {
	// Config holds configuration blocks for MatcherFactories and Matchers,
	// keyed by name.
	Config map[string]interface{} `yaml:"config,omitempty" json:"config,omitempty"`
	// A slice of strings representing which matchers will be used.
	//
	// If nil all default Matchers will be used
	//
	// The following names are supported by default:
	// "alpine"
	// "aws"
	// "debian"
	// "oracle"
	// "photon"
	// "python"
	// "rhel"
	// "suse"
	// "ubuntu"
	// "crda" - remotematcher calls hosted api via RPC.
	Names []string `yaml:"names,omitempty" json:"names,omitempty"`
}
