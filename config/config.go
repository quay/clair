package config

import (
	"fmt"
	"strings"
)

// Clair Modes
const (
	// Run this mode to create receive Manifests and create IndexReports.
	IndexerMode = "indexer"
	// Run this mode to retrieve IndexReports and create VulnerabilityReports.
	MatcherMode = "matcher"
	// Run this mode to run all modes in a single Clair instance.
	ComboMode = "combo"
	// Run this mode to listen for Updates and send notifications when they occur.
	NotifierMode = "notifier"
)

// DefaultAddress is used if an http_listen_addr is not provided in the config.
const DefaultAddress = ":6060"

// Config is the configuration object for the commands in
// github.com/quay/clair/v4/cmd/...
type Config struct {
	// One of the following strings
	// Sets which mode the clair instances will run in
	//
	// "indexer": runs just the indexer node
	// "matcher": runs just the matcher node
	// "combo":	will run both indexer and matcher on the same node.
	Mode string `yaml:"-" json:"-"`
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
	//
	// One of the following strings:
	// "debug-color"
	// "debug"
	// "info"
	// "warn"
	// "error"
	// "fatal"
	// "panic"
	LogLevel string   `yaml:"log_level" json:"log_level"`
	Indexer  Indexer  `yaml:"indexer" json:"indexer"`
	Matcher  Matcher  `yaml:"matcher" json:"matcher"`
	Matchers Matchers `yaml:"matchers" json:"matchers"`
	Updaters Updaters `yaml:"updaters,omitempty" json:"updaters,omitempty"`
	Notifier Notifier `yaml:"notifier" json:"notifier"`
	Auth     Auth     `yaml:"auth" json:"auth"`
	Trace    Trace    `yaml:"trace" json:"trace"`
	Metrics  Metrics  `yaml:"metrics" json:"metrics"`
}

// Validate confirms the necessary values to support
// the desired Clair mode exist.
func Validate(conf *Config) error {
	if conf.HTTPListenAddr == "" {
		conf.HTTPListenAddr = DefaultAddress
	}
	if conf.Matcher.DisableUpdaters {
		conf.Updaters.Sets = []string{}
	}
	switch strings.ToLower(conf.Mode) {
	case ComboMode:
		if err := conf.Indexer.Validate(true); err != nil {
			return err
		}
		if err := conf.Matcher.Validate(true); err != nil {
			return err
		}
		if err := conf.Notifier.Validate(true); err != nil {
			return err
		}
	case IndexerMode:
		if err := conf.Indexer.Validate(false); err != nil {
			return err
		}
	case MatcherMode:
		if err := conf.Matcher.Validate(false); err != nil {
			return err
		}
	case NotifierMode:
		if err := conf.Notifier.Validate(false); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown mode received: %v", conf.Mode)
	}
	return nil
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
