package config

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/quay/claircore/libvuln/driver"
	"gopkg.in/yaml.v3"
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
	Notifier Notifier `yaml:"notifier" json:"notifier"`
	Auth     Auth     `yaml:"auth" json:"auth"`
	Trace    Trace    `yaml:"trace" json:"trace"`
	Metrics  Metrics  `yaml:"metrics" json:"metrics"`
	Updaters Updaters `yaml:"updaters,omitempty" json:"updaters,omitempty"`
}

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
		if conf.Matcher.Period == 0 {
			conf.Matcher.Period = 30 * time.Minute
		}
		if conf.Matcher.UpdateRetention < 2 {
			conf.Matcher.UpdateRetention = 10
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
		if conf.Matcher.Period == 0 {
			conf.Matcher.Period = 30 * time.Minute
		}
		if conf.Matcher.UpdateRetention < 2 {
			conf.Matcher.UpdateRetention = 10
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
