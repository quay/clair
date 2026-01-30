package config

import (
	"slices"
	"time"
)

// API holds configuration for the Clair API services.
type API struct {
	// V1 is the configuration for the HTTP v1 API.
	V1 APIv1 `yaml:"v1,omitempty" json:"v1,omitempty"`
}

func (a *API) validate(_ Mode) ([]Warning, error) {
	// TODO(hank) When there's an "UpdaterMode," don't bother with validating
	// the API configurations.

	enabled := slices.ContainsFunc([]*bool{}, func(e *bool) bool {
		return e != nil && *e
	})
	// With multiple versions, the highest one should be the default, probably.
	if !enabled {
		a.V1.Enabled = &[]bool{true}[0] // TODO(go1.26) Use the "new(true)" syntax.
	}

	return nil, nil
}

// APIv1 holds configuration values for the HTTP v1 API.
type APIv1 struct {
	// Enabled configures enabling the API server at all.
	// The set of API endpoints served by any one process depends on the mode
	// the process is started in.
	//
	// If unset, defaults to "true".
	Enabled *bool `yaml:"enabled" json:"enabled"`

	// Network configures the network type to be used for serving API requests.
	//
	// If unset, [DefaultAPIv1Network] will be used.
	// See also: [net.Dial].
	Network string `yaml:"network" json:"network"`

	// Address configures the address to listen on for serving API requests.
	// The format depends on the "network" member.
	//
	// If unset, [DefaultAPIv1Address] will be used.
	// See also: [net.Dial].
	Address string `yaml:"address" json:"address"`

	// IdleTimeout configures whether the Clair process should exit after not
	// handling any requests for a specified non-zero duration.
	IdleTimeout Duration `yaml:"idle_timeout" json:"idle_timeout"`

	// TLS configures HTTPS support.
	//
	// Note that any non-trivial deployment means the certificate provided here
	// will need to be for the name the load balancer used to connect to a given
	// Clair instance.
	TLS *TLS `yaml:"tls,omitempty" json:"tls,omitempty"`
}

func (a *APIv1) validate(_ Mode) ([]Warning, error) {
	if a.Enabled == nil || !*a.Enabled {
		return nil, nil
	}
	if a.Network == "" {
		a.Network = DefaultAPIv1Network
	}
	if a.Address == "" {
		a.Address = DefaultAPIv1Address
	}

	return a.lint()
}

func (a *APIv1) lint() (ws []Warning, err error) {
	if a.Network == "" {
		ws = append(ws, Warning{
			path: ".network",
			msg:  `listen network not provided, default will be used`,
		})
	}
	if a.Address == "" {
		ws = append(ws, Warning{
			path: ".address",
			msg:  `listen address not provided, default will be used`,
		})
	}

	switch dur := time.Duration(a.IdleTimeout); {
	case dur == 0: // OK, disabled.
	case dur < (2 * time.Minute):
		ws = append(ws, Warning{
			path: ".idle_timeout",
			msg:  `idle timeout seems short, may cause frequent startups`,
		})
	default: // OK, reasonably long.
	}

	return ws, nil
}
