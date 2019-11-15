package main

type Config struct {
	HTTPListenAddr string `yaml:"http_listen_addr"`
	LogLevel       string `yaml:"http_listen_addr"`
	Indexer        *Indexer
	Matcher        *Matcher
}

type Indexer struct {
	// the backing datastore to use. implemented: postgres
	DataStore string `yaml: "datastore"`
	// the conn string to the datastore
	ConnString string `yaml: "connstring"`
	// the backing infra for locking scans. implemented: postgres
	ScanLock string `yaml: "scanlock"`
	// the interval in seconds to retry a manifest scan if the lock was not acquired
	ScanLockRetry int `yaml: "scanlock_retry"`
	// number of concurrent scans allowed on a manifest's layers. tunable for db performance
	LayerScanConcurrency int `yaml: "layer_scan_concurrency"`
}

type Matcher struct {
	// the backing store to use. implemented: postgres
	DataStore string `yaml: "datastore"`
	// the conn string to the datastore
	ConnString string `yaml: "connstring"`
	// the backing infra for locking vulnerability updates. implemented: postgres
	UpdateLock string `yaml: "update_lock"`
	// if sql usage, the connection pool size
	MaxConnPool int `yaml: "max_conn_pool"`
	// a regex pattern of updaters to run
	Run string `yaml: "run"`
	// the address where the indexer service can be reached
	IndexerAddr `yaml: "indexer_addr"`
}
