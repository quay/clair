package config

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

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
	// A positive values representing quantity.
	//
	// Indexers will index a Manifest's layers concurrently.
	// This value tunes the number of layers an Indexer will scan in parallel.
	LayerScanConcurrency int `yaml:"layer_scan_concurrency" json:"layer_scan_concurrency"`
	// Rate limits the number if index report creation requests.
	//
	// Any value below 1 is considered unlimited.
	// The API will return a 429 status code if concurrency is exceeded.
	IndexReportRequestConcurrency int `yaml:"index_report_request_concurrency" json:"index_report_request_concurrency"`
	// A "true" or "false" value
	//
	// Whether Indexer nodes handle migrations to their database.
	Migrations bool `yaml:"migrations" json:"migrations"`
	// Scanner allows for passing configuration options to layer scanners.
	Scanner ScannerConfig `yaml:"scanner" json:"scanner"`
	// Airgap disables scanners that have signaled they expect to talk to the
	// Internet.
	Airgap bool `yaml:"airgap" json:"airgap"`
}

func (i *Indexer) Validate(combo bool) error {
	const (
		DefaultScanLockRetry = 1
	)
	if i.ConnString == "" {
		return fmt.Errorf("indexer mode requires a database connection string")
	}
	if i.ScanLockRetry == 0 {
		i.ScanLockRetry = DefaultScanLockRetry
	}
	return nil
}

type ScannerConfig struct {
	Package map[string]yaml.Node `yaml:"package" json:"package"`
	Dist    map[string]yaml.Node `yaml:"dist" json:"dist"`
	Repo    map[string]yaml.Node `yaml:"repo" json:"repo"`
}
