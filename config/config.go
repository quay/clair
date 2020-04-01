package config

import (
	"fmt"
	"net/url"
	"strings"
)

// These are the mode arguments that calling code can use in the Mode member of
// a Config struct. They're called out here for documentation.
const (
	// IndexerMode receives claircore.Manifests, indexes their contents, and
	// returns claircore.IndexReports.
	IndexerMode = "indexer"
	// MatcherMode populates and updates the vulnerability database and creates
	// claircore.VulnerabilityReports from claircore.IndexReports.
	MatcherMode = "matcher"
	// ComboMode runs all services in a single process.
	ComboMode = "combo"
	// NofitierMode runs a notifier to provide notifications for upstream
	// clients.
	NotifierMode = "notifier"
)

type Config struct {
	// Mode indicates a Clair node's operational mode.
	//
	// This should be set by code that's populating and validating a config.
	Mode string `yaml:"-"`
	// indicates the HTTP listen address
	HTTPListenAddr string `yaml:"http_listen_addr"`
	// IntrospectionAddr is an address to listen on for introspection http
	// endpoints, e.g. metrics and profiling.
	//
	// If not provided, a random port will be chosen.
	IntrospectionAddr string `yaml:"introspection_addr"`
	// indicates log level for the process
	LogLevel string `yaml:"log_level"`
	// indexer mode specific config
	Indexer Indexer `yaml:"indexer"`
	// matcher mode specific config
	Matcher Matcher `yaml:"matcher"`
	Auth    Auth    `yaml:"auth"`
	// Tracing config
	Trace Trace `yaml:"trace"`
	// Metrics config
	Metrics Metrics `yaml:"metrics"`
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

type Indexer struct {
	// the conn string to the datastore
	ConnString string `yaml:"connstring"`
	// the interval in seconds to retry a manifest scan if the lock was not acquired
	ScanLockRetry int `yaml:"scanlock_retry"`
	// number of concurrent scans allowed on a manifest's layers. tunable for db performance
	LayerScanConcurrency int `yaml:"layer_scan_concurrency"`
	// should the Indexer be responsible for setting up the database
	Migrations bool `yaml:"migrations"`
}

type Matcher struct {
	// the conn string to the datastore
	ConnString string `yaml:"connstring"`
	// if sql usage, the connection pool size
	MaxConnPool int `yaml:"max_conn_pool"`
	// the address where the indexer service can be reached
	IndexerAddr string `yaml:"indexer_addr"`
	// should the Matcher be responsible for setting up the database
	Migrations bool `yaml:"migrations"`
	// Updaters is a regexp used to determine which enabled updaters to run.
	Updaters *string `yaml:"updaters"`
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

// DefaultAddress is used if an http_listen_addr is not provided in the config.
const DefaultAddress = ":6060"

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
