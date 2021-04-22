package config

import (
	"fmt"
	"net/url"
	"time"
)

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
	Period time.Duration `yaml:"period" json:"period"`
	// DisableUpdaters disables the updater's running of matchers.
	//
	// This should be toggled on if vulnerabilities are being provided by
	// another mechanism.
	DisableUpdaters bool `yaml:"disable_updaters" json:"disable_updaters"`
	// UpdateRetention controls the number of updates to retain between
	// garbage collection periods.
	//
	// The lowest possible value is 2 in order to compare updates for notification
	// purposes.
	//
	// A value of 0 disables GC.
	UpdateRetention int `yaml:"update_retention" json:"update_retention"`
}

func (m *Matcher) Validate(combo bool) error {
	const (
		DefaultPeriod    = 30 * time.Minute
		DefaultRetention = 10
	)
	if m.ConnString == "" {
		return fmt.Errorf("matcher requires a database connection string")
	}
	if m.Period == 0 {
		m.Period = DefaultPeriod
	}
	if m.UpdateRetention == 1 || m.UpdateRetention < 0 {
		m.UpdateRetention = DefaultRetention
	}
	if !combo {
		if m.IndexerAddr == "" {
			return fmt.Errorf("matcher mode requires a remote Indexer address")
		}
		_, err := url.Parse(m.IndexerAddr)
		if err != nil {
			return fmt.Errorf("failed to parse matcher mode IndexerAddr string: %v", err)
		}
	}
	return nil
}
