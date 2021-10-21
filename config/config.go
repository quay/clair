package config

import (
	"fmt"
	"net"
)

// DefaultAddress is used if an http_listen_addr is not provided in the config.
const DefaultAddress = ":6060"

// Config is the configuration object for the commands in
// github.com/quay/clair/v4/cmd/...
type Config struct {
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
