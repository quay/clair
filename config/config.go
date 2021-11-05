package config

import (
	"fmt"
	"net"
)

// Config is the configuration object for the commands in
// github.com/quay/clair/v4/cmd/...
type Config struct {
	// TLS configures HTTPS support.
	//
	// Note that any non-trivial deployment means the certificate provided here
	// will need to be for the name the load balancer uses to connect to a given
	// Clair instance.
	//
	// This is not used for outgoing requests; setting the SSL_CERT_DIR
	// environment variable is the recommended way to do that. The release
	// container has `/var/run/certs` added to the list already.
	TLS *TLS `yaml:"tls,omitempty" json:"tls,omitempty"`
	// Sets which mode the clair instance will run.
	Mode Mode `yaml:"-" json:"-"`
	// A string in <host>:<port> format where <host> can be an empty string.
	//
	// exposes Clair node's functionality to the network.
	// see /openapi/v1 for api spec.
	HTTPListenAddr string `yaml:"http_listen_addr" json:"http_listen_addr"`
	// A string in <host>:<port> format where <host> can be an empty string.
	//
	// exposes Clair's metrics and health endpoints.
	IntrospectionAddr string `yaml:"introspection_addr" json:"introspection_addr"`
	// Set the logging level.
	LogLevel LogLevel `yaml:"log_level" json:"log_level"`
	Indexer  Indexer  `yaml:"indexer" json:"indexer"`
	Matcher  Matcher  `yaml:"matcher" json:"matcher"`
	Matchers Matchers `yaml:"matchers" json:"matchers"`
	Updaters Updaters `yaml:"updaters,omitempty" json:"updaters,omitempty"`
	Notifier Notifier `yaml:"notifier" json:"notifier"`
	Auth     Auth     `yaml:"auth" json:"auth"`
	Trace    Trace    `yaml:"trace" json:"trace"`
	Metrics  Metrics  `yaml:"metrics" json:"metrics"`
}

func (c *Config) validate(mode Mode) ([]Warning, error) {
	if c.HTTPListenAddr == "" {
		c.HTTPListenAddr = DefaultAddress
	}
	if c.Matcher.DisableUpdaters {
		c.Updaters.Sets = []string{}
	}
	switch mode {
	case ComboMode, IndexerMode, MatcherMode, NotifierMode:
		// OK
	default:
		return nil, fmt.Errorf("unknown mode: %q", mode)
	}
	if _, _, err := net.SplitHostPort(c.HTTPListenAddr); err != nil {
		return nil, err
	}
	return c.lint()
}

func (c *Config) lint() (ws []Warning, err error) {
	if c.HTTPListenAddr == "" {
		ws = append(ws, Warning{
			path: ".http_listen_addr",
			msg:  `http listen address not provided, default will be used`,
		})
	}
	if c.IntrospectionAddr == "" {
		ws = append(ws, Warning{
			path: ".introspection_addr",
			msg:  `introspection address not provided, default will be used`,
		})
	}
	return ws, nil
}
