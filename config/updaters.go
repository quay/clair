package config

// Updaters configures updater behavior.
type Updaters struct {
	// Filter is a regexp that disallows updaters that do not match from
	// running.
	// TODO(louis): this is only used in clairctl, should we keep this?
	// it may offer an escape hatch for a particular updater name
	// from running, vs disabling the updater set completely.
	Filter string `yaml:"filter,omitempty" json:"filter,omitempty"`
	// Config holds configuration blocks for UpdaterFactories and Updaters,
	// keyed by name.
	//
	// These are defined by the updater implementation and can't be documented
	// here. Improving the documentation for these is an open issue.
	Config map[string]interface{} `yaml:"config,omitempty" json:"config,omitempty"`
	// A slice of strings representing which updaters will be used.
	//
	// If nil all default UpdaterSets will be used
	//
	// The following sets are supported by default:
	// "alpine"
	// "aws"
	// "clair.cvss"
	// "debian"
	// "oracle"
	// "osv"
	// "photon"
	// "rhcc"
	// "rhel"
	// "suse"
	// "ubuntu"
	Sets []string `yaml:"sets,omitempty" json:"sets,omitempty"`
}
