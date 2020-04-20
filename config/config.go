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
	Mode string `yaml:"-"`
	// A string in <host>:<port> format where <host> can be an empty string.
	//
	// exposes Clair node's functionality to the network.
	// see /openapi/v1 for api spec.
	HTTPListenAddr string `yaml:"http_listen_addr"`
	// A string in <host>:<port> format where <host> can be an empty string.
	//
	// exposes Clair's metrics and health endpoints.
	IntrospectionAddr string `yaml:"introspection_addr"`
	// One of the following srings
	// Sets the logging level
	//
	// "debug-color"
	// "debug"
	// "info"
	// "warn"
	// "error"
	// "fatal"
	// "panic"
	LogLevel string `yaml:"log_level"`
	// See Indexer for details
	Indexer Indexer `yaml:"indexer"`
	// See Matcher for details
	Matcher Matcher `yaml:"matcher"`
	Auth    Auth    `yaml:"auth"`
	Trace   Trace   `yaml:"trace"`
	Metrics Metrics `yaml:"metrics"`
}

// Indexer provides Clair Indexer node configuration
type Indexer struct {
	// A POSTGRES connection string
	//
	// formats
	// url: "postgres://pqgotest:password@localhost/pqgotest?sslmode=verify-full"
	// or
	// string: "user=pqgotest dbname=pqgotest sslmode=verify-full"
	ConnString string `yaml:"connstring"`
	// A positive value representing seconds.
	//
	// Concurrent Indexers lock on manifest scans to avoid clobbering.
	// This value tunes how often a waiting Indexer will poll for the lock.
	// TODO: Move to async operating mode
	ScanLockRetry int `yaml:"scanlock_retry"`
	// A positive values represeting quantity.
	//
	// Indexers will index a Manifest's layers concurrently.
	// This value tunes the number of layers an Indexer will scan in parallel.
	LayerScanConcurrency int `yaml:"layer_scan_concurrency"`
	// A "true" or "false" value
	//
	// Whether Indexer nodes handle migrations to their database.
	Migrations bool `yaml:"migrations"`
}

type Matcher struct {
	// A POSTGRES connection string
	//
	// Formats:
	// url: "postgres://pqgotest:password@localhost/pqgotest?sslmode=verify-full"
	// or
	// string: "user=pqgotest dbname=pqgotest sslmode=verify-full"
	ConnString string `yaml:"connstring"`
	// A positive integer
	//
	// Clair allows for a custom connection pool size.
	// This number will directly set how many active sql
	// connections are allowed concurrently.
	MaxConnPool int `yaml:"max_conn_pool"`
	// A string in <host>:<port> format where <host> can be an empty string.
	//
	// A Matcher contacts an Indexer to create a VulnerabilityReport.
	// The location of this Indexer is required.
	IndexerAddr string `yaml:"indexer_addr"`
	// A "true" or "false" value
	//
	// Whether Matcher nodes handle migrations to their databases.
	Migrations bool `yaml:"migrations"`
	// A Regex string
	//
	// When the Matcher is provided a regex string it will use
	// this string to limit the created updaters.
	//
	// If the provided string matches no updaters no updaters
	// will be running.
	Updaters *string `yaml:"updaters"`
}

// Auth holds the specific configs for different authentication methods.
//
// These should be pointers to structs, so that it's possible to distinguish
// between "absent" and "present and misconfigured."
type Auth struct {
	PSK       *AuthPSK       `yaml:"psk,omitempty"`
	Keyserver *AuthKeyserver `yaml:"keyserver,omitempty"`
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
	API          string `yaml:"api"`
	Intraservice []byte `yaml:"intraservice"`
}

// AuthPSK is the configuration for doing pre-shared key based authentication.
//
// The "Issuer" key is what the service expects to verify as the "issuer claim.
type AuthPSK struct {
	Key    []byte `yaml:"key"`
	Issuer string `yaml:"iss"`
}

type Trace struct {
	Name        string   `yaml:"name"`
	Probability *float64 `yaml:"probability"`
	Jaeger      Jaeger   `yaml:"jaeger"`
}

type Jaeger struct {
	Agent struct {
		Endpoint string `yaml:"agent_endpoint"`
	} `yaml:",inline"`
	Collector struct {
		Endpoint string  `yaml:"collector_endpoint"`
		Username *string `yaml:"username"`
		Password *string `yaml:"password"`
	} `yaml:",inline"`
	ServiceName string            `yaml:"service_name"`
	Tags        map[string]string `yaml:"tags"`
	BufferMax   int               `yaml:"buffer_max"`
}

type Metrics struct {
	Name       string     `yaml:"name"`
	Prometheus Prometheus `yaml:"prometheus"`
	Dogstatsd  Dogstatsd  `yaml:"dogstatsd"`
}

type Prometheus struct {
	Endpoint *string `yaml:"endpoint"`
}

type Dogstatsd struct {
	URL string `yaml:"url"`
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
