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
	// indicates the listening http address if mode is 'indexer'
	HTTPListenAddr string `yaml:"http_listen_addr"`
	// indicates log level for the process
	LogLevel string `yaml:"log_level"`
	// indexer mode specific config
	Indexer Indexer `yaml: "indexer"`
	// matcher mode specific config
	Matcher Matcher `yaml: "matcher"`
}

type Indexer struct {
	// indicates the listening http address if mode is 'indexer'
	HTTPListenAddr string `yaml:"http_listen_addr"`
	// the conn string to the datastore
	ConnString string `yaml: "connstring"`
	// the interval in seconds to retry a manifest scan if the lock was not acquired
	ScanLockRetry int `yaml: "scanlock_retry"`
	// number of concurrent scans allowed on a manifest's layers. tunable for db performance
	LayerScanConcurrency int `yaml: "layer_scan_concurrency"`
}

type Matcher struct {
	// indicates the listening http address if mode is 'matcher'
	HTTPListenAddr string `yaml:"http_listen_addr"`
	// the conn string to the datastore
	ConnString string `yaml: "connstring"`
	// if sql usage, the connection pool size
	MaxConnPool int `yaml: "max_conn_pool"`
	// a regex pattern of updaters to run
	Run string `yaml: "run"`
	// the address where the indexer service can be reached
	IndexerAddr string `yaml: "indexer_addr"`
}

func Validate(conf Config) error {
	switch strings.ToLower(conf.Mode) {
	case DevMode:
		if conf.HTTPListenAddr == "" {
			return fmt.Errorf("dev mode selected but no global HTTPListenAddr")
		}
		_, err := url.Parse(conf.HTTPListenAddr)
		if err != nil {
			return fmt.Errorf("failed to url parse dev mode HTTPListenAddr string: %w", err)
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

		_, err := url.Parse(conf.Indexer.HTTPListenAddr)
		if err != nil {
			return fmt.Errorf("failed to parse indexer HTTPListenAddr string: %w", err)
		}

		if conf.Indexer.ConnString == "" {
			return fmt.Errorf("indexer mode requires a database connection string")
		}
	case MatcherMode:
		if conf.Matcher.HTTPListenAddr == "" {
			return fmt.Errorf("matcher mode selected but no http listen address")
		}

		_, err := url.Parse(conf.Matcher.HTTPListenAddr)
		if err != nil {
			return fmt.Errorf("failed to url parse matcher mode HTTPListenAddr string: %v", err)
		}

		if conf.Matcher.ConnString == "" {
			return fmt.Errorf("matcher mode requires a database connection string")
		}

		if conf.Matcher.IndexerAddr == "" {
			return fmt.Errorf("matcher mode requires a remote Indexer address")
		}

		_, err = url.Parse(conf.Matcher.HTTPListenAddr)
		if err != nil {
			return fmt.Errorf("failed to url parse matcher mode IndexAddr string: %v", err)
		}
	default:
		return fmt.Errorf("unknown mode received: %v", conf.Mode)
	}
	return nil
}
