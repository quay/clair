package config

import (
	"github.com/quay/claircore/libvuln/driver"
	"gopkg.in/yaml.v3"
)

// Updaters configures updater behavior.
type Updaters struct {
	// A slice of strings representing which
	// updaters will be used.
	//
	// If nil all default UpdaterSets will be used
	//
	// The following sets are supported by default:
	// "alpine"
	// "aws"
	// "debian"
	// "oracle"
	// "photon"
	// "pyupio"
	// "rhel"
	// "suse"
	// "ubuntu"
	Sets []string `yaml:"sets,omitempty" json:"sets,omitempty"`
	// Config holds configuration blocks for UpdaterFactories and Updaters,
	// keyed by name.
	//
	// These are defined by the updater implementation and can't be documented
	// here. Improving the documentation for these is an open issue.
	Config map[string]yaml.Node `yaml:"config" json:"config"`
	// Filter is a regexp that disallows updaters that do not match from
	// running.
	// TODO(louis): this is only used in clairctl, should we keep this?
	// it may offer an escape hatch for a particular updater name
	// from running, vs disabling the updater set completely.
	Filter string `yaml:"filter" json:"filter"`
}

func (u *Updaters) FilterSets(m map[string]driver.UpdaterSetFactory) {
	if u.Sets != nil {
	Outer:
		for k := range m {
			for _, n := range u.Sets {
				if k == n {
					continue Outer
				}
			}
			delete(m, k)
		}
	}
	return
}
