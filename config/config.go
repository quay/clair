package config

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"

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
	LogLevel string `yaml:"log_level" json:"log_level"`
	// See Indexer for details
	Indexer Indexer `yaml:"indexer" json:"indexer"`
	// See Matcher for details
	Matcher Matcher `yaml:"matcher" json:"matcher"`
	Auth    Auth    `yaml:"auth" json:"auth"`
	Trace   Trace   `yaml:"trace" json:"trace"`
	Metrics Metrics `yaml:"metrics" json:"metrics"`
}

// Indexer provides Clair Indexer node configuration
type Indexer struct {
	// A Postgres connection string.
	//
	// formats
	// url: "postgres://pqgotest:password@localhost/pqgotest?sslmode=verify-full"
	// or
	// string: "user=pqgotest dbname=pqgotest sslmode=verify-full"
	ConnString string `yaml:"connstring" json:"connstring"`
	// A positive value representing seconds.
	//
	// Concurrent Indexers lock on manifest scans to avoid clobbering.
	// This value tunes how often a waiting Indexer will poll for the lock.
	// TODO: Move to async operating mode
	ScanLockRetry int `yaml:"scanlock_retry" json:"scanlock_retry"`
	// A positive values represeting quantity.
	//
	// Indexers will index a Manifest's layers concurrently.
	// This value tunes the number of layers an Indexer will scan in parallel.
	LayerScanConcurrency int `yaml:"layer_scan_concurrency" json:"layer_scan_concurrency"`
	// A "true" or "false" value
	//
	// Whether Indexer nodes handle migrations to their database.
	Migrations bool `yaml:"migrations" json:"migrations"`
	// Scanner allows for passing configuration options to layer scanners.
	Scanner map[string]yaml.Node `yaml:"scanner" json:"scanner"`
}

type Matcher struct {
	// A Postgres connection string.
	//
	// Formats:
	// url: "postgres://pqgotest:password@localhost/pqgotest?sslmode=verify-full"
	// or
	// string: "user=pqgotest dbname=pqgotest sslmode=verify-full"
	ConnString string `yaml:"connstring" json:"connstring"`
	// A positive integer
	//
	// Clair allows for a custom connection pool size.
	// This number will directly set how many active sql
	// connections are allowed concurrently.
	MaxConnPool int `yaml:"max_conn_pool" json:"max_conn_pool"`
	// A string in <host>:<port> format where <host> can be an empty string.
	//
	// A Matcher contacts an Indexer to create a VulnerabilityReport.
	// The location of this Indexer is required.
	IndexerAddr string `yaml:"indexer_addr" json:"indexer_addr"`
	// A "true" or "false" value
	//
	// Whether Matcher nodes handle migrations to their databases.
	Migrations bool `yaml:"migrations" json:"migrations"`
	// A slice of strings representing which
	// updaters matcher will create.
	//
	// If nil all default UpdaterSets will be used
	//
	// The following sets are supported:
	// "alpine"
	// "aws"
	// "debian"
	// "oracle"
	// "photon"
	// "pyupio"
	// "rhel"
	// "suse"
	// "ubuntu"
	UpdaterSets []string `yaml:"updater_sets" json:"updater_sets"`
}

// Auth holds the specific configs for different authentication methods.
//
// These should be pointers to structs, so that it's possible to distinguish
// between "absent" and "present and misconfigured."
type Auth struct {
	PSK       *AuthPSK       `yaml:"psk,omitempty" json:"psk,omitempty"`
	Keyserver *AuthKeyserver `yaml:"keyserver,omitempty" json:"keyserver,omitempty"`
}

// Any reports whether any sort of authentication is configured.
func (a Auth) Any() bool {
	return a.PSK != nil ||
		a.Keyserver != nil
}

// AuthKeyserver is the configuration for doing authentication with the Quay
// keyserver protocol.
//
// The "Intraservice" key is only needed when the overall config mode is not
// "combo".
type AuthKeyserver struct {
	API          string `yaml:"api" json:"api"`
	Intraservice []byte `yaml:"intraservice" json:"intraservice"`
}

// UnmarshalYAML implements yaml.Unmarshaler.
func (a *AuthKeyserver) UnmarshalYAML(f func(interface{}) error) error {
	var m struct {
		API          string `yaml:"api" json:"api"`
		Intraservice string `yaml:"intraservice" json:"intraservice"`
	}
	if err := f(&m); err != nil {
		return nil
	}
	a.API = m.API
	s, err := base64.StdEncoding.DecodeString(m.Intraservice)
	if err != nil {
		return err
	}
	a.Intraservice = s
	return nil
}

// AuthPSK is the configuration for doing pre-shared key based authentication.
//
// The "Issuer" key is what the service expects to verify as the "issuer claim.
type AuthPSK struct {
	Key    []byte `yaml:"key" json:"key"`
	Issuer string `yaml:"iss" json:"iss"`
}

// UnmarshalYAML implements yaml.Unmarshaler.
func (a *AuthPSK) UnmarshalYAML(f func(interface{}) error) error {
	var m struct {
		Issuer string `yaml:"iss" json:"iss"`
		Key    string `yaml:"key" json:"key"`
	}
	if err := f(&m); err != nil {
		return nil
	}
	a.Issuer = m.Issuer
	s, err := base64.StdEncoding.DecodeString(m.Key)
	if err != nil {
		return err
	}
	a.Key = s
	return nil
}

type Trace struct {
	Name        string   `yaml:"name" json:"name"`
	Probability *float64 `yaml:"probability" json:"probability"`
	Jaeger      Jaeger   `yaml:"jaeger" json:"jaeger"`
}

type Jaeger struct {
	Agent struct {
		Endpoint string `yaml:"agent_endpoint" json:"agent_endpoint"`
	} `yaml:",inline" json:",inline"`
	Collector struct {
		Endpoint string  `yaml:"collector_endpoint" json:"collector_endpoint"`
		Username *string `yaml:"username" json:"username"`
		Password *string `yaml:"password" json:"password"`
	} `yaml:",inline" json:",inline"`
	ServiceName string            `yaml:"service_name" json:"service_name"`
	Tags        map[string]string `yaml:"tags" json:"tags"`
	BufferMax   int               `yaml:"buffer_max" json:"buffer_max"`
}

type Metrics struct {
	Name       string     `yaml:"name" json:"name"`
	Prometheus Prometheus `yaml:"prometheus" json:"prometheus"`
	Dogstatsd  Dogstatsd  `yaml:"dogstatsd" json:"dogstatsd"`
}

type Prometheus struct {
	Endpoint *string `yaml:"endpoint" json:"endpoint"`
}

type Dogstatsd struct {
	URL string `yaml:"url" json:"url"`
}

// Validate confirms the required config values are present
// and sets defaults where sane to do so.
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
	default:
		return fmt.Errorf("unknown mode received: %v", conf.Mode)
	}
	return nil
}
