package config

import "runtime"

// Indexer provides Clair Indexer node configuration
type Indexer struct {
	// Scanner allows for passing configuration options to layer scanners.
	Scanner ScannerConfig `yaml:"scanner,omitempty" json:"scanner,omitempty"`
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
	ScanLockRetry int `yaml:"scanlock_retry,omitempty" json:"scanlock_retry,omitempty"`
	// A positive values representing quantity.
	//
	// Indexers will index a Manifest's layers concurrently.
	// This value tunes the number of layers an Indexer will scan in parallel.
	LayerScanConcurrency int `yaml:"layer_scan_concurrency,omitempty" json:"layer_scan_concurrency,omitempty"`
	// Rate limits the number of index report creation requests.
	//
	// Setting this to 0 will attempt to auto-size this value. Setting a
	// negative value means "unlimited." The auto-sizing is a multiple of the
	// number of available cores.
	//
	// The API will return a 429 status code if concurrency is exceeded.
	IndexReportRequestConcurrency int `yaml:"index_report_request_concurrency,omitempty" json:"index_report_request_concurrency,omitempty"`
	// A "true" or "false" value
	//
	// Whether Indexer nodes handle migrations to their database.
	Migrations bool `yaml:"migrations,omitempty" json:"migrations,omitempty"`
	// Airgap disables HTTP access to the Internet. This affects both indexers and
	// the layer fetcher. Database connections are unaffected.
	//
	// "Airgap" is a bit of a misnomer, as [RFC 4193] and [RFC 1918] addresses
	// are always allowed. This means that setting this flag and also
	// configuring a proxy on a private network does not prevent contact with
	// the Internet.
	//
	// [RFC 1918]: https://datatracker.ietf.org/doc/html/rfc1918
	// [RFC 4193]: https://datatracker.ietf.org/doc/html/rfc4193
	Airgap bool `yaml:"airgap,omitempty" json:"airgap,omitempty"`
}

func (i *Indexer) validate(mode Mode) (ws []Warning, err error) {
	const DefaultScanLockRetry = 1
	if mode != ComboMode && mode != IndexerMode {
		return nil, nil
	}
	if i.ScanLockRetry == 0 {
		i.ScanLockRetry = DefaultScanLockRetry
	}
	if i.IndexReportRequestConcurrency == 0 {
		// GOMAXPROCS should be set to the number of cores available.
		gmp := runtime.GOMAXPROCS(0)
		const wildGuess = 4
		i.IndexReportRequestConcurrency = gmp * wildGuess
		ws = append(ws, Warning{
			path: ".index_report_request_concurrency",
			msg:  `automatically sizing number of concurrent requests`,
		})
	}
	lws, err := i.lint()
	return append(ws, lws...), err
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

	return ws, nil
}

// ScannerConfig is the object consulted for configuring the various types of
// scanners.
type ScannerConfig struct {
	Package map[string]interface{} `yaml:"package,omitempty" json:"package,omitempty"`
	Dist    map[string]interface{} `yaml:"dist,omitempty" json:"dist,omitempty"`
	Repo    map[string]interface{} `yaml:"repo,omitempty" json:"repo,omitempty"`
}
