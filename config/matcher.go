package config

import "time"

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
	// Period controls how often updaters are run.
	//
	// The default is 30 minutes.
	Period *time.Duration `yaml:"period" json:"period"`
	// DisableUpdaters disables the updater's running of matchers.
	//
	// This should be toggled on if vulnerabilities are being provided by
	// another mechanism.
	DisableUpdaters bool `yaml:"disable_updaters" json:"disable_updaters"`
}
