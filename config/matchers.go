package config

import (
	"gopkg.in/yaml.v3"
)

type Matchers struct {
	// A slice of strings representing which
	// matchers will be used.
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
	Names []string `yaml:"names" json:"names"`
	// Config holds configuration blocks for MatcherFactories and Matchers,
	// keyed by name.
	Config map[string]yaml.Node `yaml:"config" json:"config"`
}
