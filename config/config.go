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
			return fmt.Errorf("all mode selected but no global http listen address")
		}
		_, err := url.Parse(conf.HTTPListenAddr)
		if err != nil {
			return fmt.Errorf("failed to parse all mode global http listen addr: %w", err)
		}

		if conf.Indexer.ConnString == "" {
			return fmt.Errorf("no connection string provided for indexer")
		}
		if conf.Matcher.ConnString == "" {
			return fmt.Errorf("no connection string provided for matcher")
		}
	case IndexerMode:
		if conf.Indexer.HTTPListenAddr == "" {
			return fmt.Errorf("indexer mode selected but no http listen address")
		}

		_, err := url.Parse(conf.Indexer.HTTPListenAddr)
		if err != nil {
			return fmt.Errorf("failed to parse indexer mode http listen addr: %w", err)
		}

		if conf.Indexer.ConnString == "" {
			return fmt.Errorf("no connection string provided for indexer")
		}
	case MatcherMode:
		if conf.Matcher.HTTPListenAddr == "" {
			return fmt.Errorf("indexer mode selected but no http listen address")
		}

		_, err := url.Parse(conf.Matcher.HTTPListenAddr)
		if err != nil {
			return fmt.Errorf("failed to parse all mode global http listen addr: %v", err)
		}

		if conf.Matcher.ConnString == "" {
			return fmt.Errorf("no connection string provided for indexer")
		}
	default:
		return fmt.Errorf("unknown mode received: %v", conf.Mode)
	}
	return nil
}
