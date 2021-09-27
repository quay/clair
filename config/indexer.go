package config

import (
	"fmt"
)

// Indexer provides Clair Indexer node configuration
type Indexer struct {
	// Scanner allows for passing configuration options to layer scanners.
	Scanner ScannerConfig `yaml:"scanner" json:"scanner"`
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

func (i *Indexer) lint() (ws []Warning, err error) {
	ws, err = checkDSN(i.ConnString)
	if err != nil {
		return ws, err
	}
	for i := range ws {
		ws[i].path = ".connstring"
	}
	if i.ScanLockRetry > 10 { // Guess at what a "large" value is here.
		ws = append(ws, Warning{
			path: ".scanlock_retry",
			msg:  `large values will increase latency`,
		})
	}
	switch {
	case i.LayerScanConcurrency == 0:
		// Skip, autosized.
	case i.LayerScanConcurrency < 4:
		ws = append(ws, Warning{
			path: ".layer_scan_concurrency",
			msg:  `small values will limit resource utilization and increase latency`,
		})
	case i.LayerScanConcurrency > 32:
		ws = append(ws, Warning{
			path: ".layer_scan_concurrency",
			msg:  `large values may exceed resource quotas`,
		})
	}
	if i.IndexReportRequestConcurrency < 1 {
		// Remove this lint if we come up with a heuristic instead of just
		// "unlimited".
		ws = append(ws, Warning{
			path: ".index_report_request_concurrency",
			msg:  `unlimited concurrent requests may exceed resource quotas`,
		})
	}

	return ws, nil
}

type ScannerConfig struct {
	Package map[string]interface{} `yaml:"package" json:"package"`
	Dist    map[string]interface{} `yaml:"dist" json:"dist"`
	Repo    map[string]interface{} `yaml:"repo" json:"repo"`
}
