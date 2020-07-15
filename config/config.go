package config

import (
	"fmt"
	"net/url"
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
	Matcher  Matcher  `yaml:"matcher"`
	Notifier Notifier `yaml:"notifier"`
	Auth     Auth     `yaml:"auth"`
	Trace    Trace    `yaml:"trace"`
	Metrics  Metrics  `yaml:"metrics"`
}

// Validate confirms the necessary values to support
// the desired Clair Mode exist
func Validate(conf Config) error {
	switch strings.ToLower(conf.Mode) {
	case ComboMode:
		if conf.HTTPListenAddr == "" {
			conf.HTTPListenAddr = DefaultAddress
		}
		if conf.Indexer.ConnString == "" {
			return fmt.Errorf("indexer mode requires a database connection string")
		}
		if conf.Matcher.ConnString == "" {
			return fmt.Errorf("matcher mode requires a database connection string")
		}
		if conf.Notifier.ConnString == "" {
			return fmt.Errorf("notifier mode requires a database connection string")
		}
	case IndexerMode:
		if conf.HTTPListenAddr == "" {
			conf.HTTPListenAddr = DefaultAddress
		}
		if conf.Indexer.ConnString == "" {
			return fmt.Errorf("indexer mode requires a database connection string")
		}
	case MatcherMode:
		if conf.HTTPListenAddr == "" {
			conf.HTTPListenAddr = DefaultAddress
		}
		if conf.Matcher.ConnString == "" {
			return fmt.Errorf("matcher mode requires a database connection string")
		}

		if conf.Matcher.IndexerAddr == "" {
			return fmt.Errorf("matcher mode requires a remote Indexer address")
		}
		_, err := url.Parse(conf.Matcher.IndexerAddr)
		if err != nil {
			return fmt.Errorf("failed to url parse matcher mode IndexAddr string: %v", err)
		}
	case NotifierMode:
		if conf.Notifier.ConnString == "" {
			return fmt.Errorf("notifier mode requires a database connection string")
		}
		if conf.Notifier.IndexerAddr == "" {
			return fmt.Errorf("notifier mode requires a remote Indexer")
		}
		if conf.Notifier.MatcherAddr == "" {
			return fmt.Errorf("notifier mode requires a remote Matcher")
		}
	default:
		return fmt.Errorf("unknown mode received: %v", conf.Mode)
	}
	return nil
}
