package config

import (
	"errors"
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
	switch strings.ToLower(conf.Mode) {
	case ComboMode:
		if err := conf.Indexer.Validate(true); err != nil {
			return err
		}
		if err := conf.Matcher.Validate(true); err != nil {
			return err
		}
		if ok, err := conf.Notifier.Any(), conf.Notifier.Validate(true); ok && err != nil {
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
		if !conf.Notifier.Any() {
			return errNeedDelivery
		}
		if err := conf.Notifier.Validate(false); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown mode received: %v", conf.Mode)
	}
	return nil
}

var errNeedDelivery = errors.New("notifier mode requires a delivery mechanism")
