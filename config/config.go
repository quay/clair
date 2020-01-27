package config

import (
	"fmt"
	"net/url"
	"strings"
)

const (
	// receives claircore.Manifest(s), indexes their contents, and returns claircore.IndexReport(s)
	IndexerMode = "indexer"
	// populates and updates the vulnerability database and creates claircore.VulnerabilityReport(s) from claircore.IndexReport(s)
	MatcherMode = "matcher"
	// runs both indexer and matcher in a single process communicating over local api
	DevMode = "dev"
)

type Config struct {
	// indicates a Clair node's operational mode
	Mode string `yaml:"mode"`
	// indicates the global listen address if running in "Dev"
	HTTPListenAddr string `yaml:"http_listen_addr"`
	// IntrospectionAddr is an address to listen on for introspection http
	// endpoints, e.g. metrics and profiling.
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

type Auth struct {
	Name   string            `yaml:"name"`
	Params map[string]string `yaml:"params"`
}

type Indexer struct {
	// indicates the listening http address if mode is 'indexer'
	HTTPListenAddr string `yaml:"http_listen_addr"`
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
	// indicates the listening http address if mode is 'matcher'
	HTTPListenAddr string `yaml:"http_listen_addr"`
	// the conn string to the datastore
	ConnString string `yaml:"connstring"`
	// if sql usage, the connection pool size
	MaxConnPool int `yaml:"max_conn_pool"`
	// a regex pattern of updaters to run
	Run string `yaml:"run"`
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
	Jaeger      Jaeger   `yaml:",inline"`
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
	Prometheus Prometheus `yaml:",inline"`
	Dogstatsd  Dogstatsd  `yaml:",inline"`
}

type Prometheus struct {
	Endpoint *string `yaml:"endpoint"`
}

type Dogstatsd struct {
	URL string `yaml:"url"`
}

func Validate(conf Config) error {
	switch strings.ToLower(conf.Mode) {
	case DevMode:
		if conf.HTTPListenAddr == "" {
			return fmt.Errorf("dev mode selected but no global HTTPListenAddr")
		}
		if conf.Indexer.ConnString == "" {
			return fmt.Errorf("indexer mode requires a database connection string")
		}
		if conf.Matcher.ConnString == "" {
			return fmt.Errorf("matcher mode requires a database connection string")
		}
	case IndexerMode:
		if conf.Indexer.HTTPListenAddr == "" {
			return fmt.Errorf("indexer mode selected but no http listen address")
		}
		if conf.Indexer.ConnString == "" {
			return fmt.Errorf("indexer mode requires a database connection string")
		}
	case MatcherMode:
		if conf.Matcher.HTTPListenAddr == "" {
			return fmt.Errorf("matcher mode selected but no http listen address")
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
