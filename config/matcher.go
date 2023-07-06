package config

import (
	"fmt"
	"net/url"
)

// Matcher is the configuration for the matcher service.
type Matcher struct {
	// A Postgres connection string.
	//
	// Formats:
	// url: "postgres://pqgotest:password@localhost/pqgotest?sslmode=verify-full"
	// or
	// string: "user=pqgotest dbname=pqgotest sslmode=verify-full"
	ConnString string `yaml:"connstring" json:"connstring"`
	// A string in <host>:<port> format where <host> can be an empty string.
	//
	// A Matcher contacts an Indexer to create a VulnerabilityReport.
	// The location of this Indexer is required.
	IndexerAddr string `yaml:"indexer_addr" json:"indexer_addr"`
	// Period controls how often updaters are run.
	//
	// The default is 6 hours.
	Period Duration `yaml:"period,omitempty" json:"period,omitempty"`
	// UpdateRetention controls the number of updates to retain between
	// garbage collection periods.
	//
	// The lowest possible value is 2 in order to compare updates for notification
	// purposes.
	//
	// A value of 0 disables GC.
	UpdateRetention int `yaml:"update_retention" json:"update_retention"`
	// A positive integer
	//
	// Clair allows for a custom connection pool size.  This number will
	// directly set how many active sql connections are allowed concurrently.
	//
	// Deprecated: Pool size should be set through the ConnString member.
	// Currently, Clair only uses the "pgxpool" package to connect to the
	// database, so see
	// https://pkg.go.dev/github.com/jackc/pgx/v4/pgxpool#ParseConfig for more
	// information.
	MaxConnPool int `yaml:"max_conn_pool,omitempty" json:"max_conn_pool,omitempty"`
	// CacheAge controls how long clients should be hinted to cache responses
	// for.
	//
	// If empty, the duration set in "Period" will be used. This means client
	// may cache "stale" results for 2(Period) - 1 seconds.
	CacheAge Duration `yaml:"cache_age,omitempty" json:"cache_age,omitempty"`
	// A "true" or "false" value
	//
	// Whether Matcher nodes handle migrations to their databases.
	Migrations bool `yaml:"migrations,omitempty" json:"migrations,omitempty"`
	// DisableUpdaters disables the updater's running of matchers.
	//
	// This should be toggled on if vulnerabilities are being provided by
	// another mechanism.
	DisableUpdaters bool `yaml:"disable_updaters,omitempty" json:"disable_updaters,omitempty"`
}

func (m *Matcher) validate(mode Mode) ([]Warning, error) {
	if mode != ComboMode && mode != MatcherMode {
		return nil, nil
	}
	if m.Period == 0 {
		m.Period = Duration(DefaultMatcherPeriod)
	}
	switch {
	case m.UpdateRetention < 0:
		// Less than 0 means GC is off.
		m.UpdateRetention = 0
	case m.UpdateRetention < 2:
		// Anything less than 2 gets the default.
		m.UpdateRetention = DefaultUpdateRetention
	}
	if m.CacheAge == 0 {
		m.CacheAge = m.Period
	}
	switch mode {
	case ComboMode:
	case MatcherMode:
		if m.IndexerAddr == "" {
			return nil, fmt.Errorf("matcher mode requires a remote Indexer address")
		}
		_, err := url.Parse(m.IndexerAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse matcher mode IndexerAddr string: %v", err)
		}
	default:
		panic("programmer error")
	}
	return m.lint()
}

func (m *Matcher) lint() (ws []Warning, err error) {
	ws, err = checkDSN(m.ConnString)
	if err != nil {
		return ws, err
	}
	for i := range ws {
		ws[i].path = ".connstring"
	}

	if m.Period < Duration(DefaultMatcherPeriod) {
		ws = append(ws, Warning{
			path: ".period",
			msg:  "updater period is very aggressive: most sources are updated daily",
		})
	}
	if m.CacheAge < m.Period/2 {
		ws = append(ws, Warning{
			path: ".cache_age",
			msg:  "expiry very low: may result in increased workload",
		})
	}
	if m.UpdateRetention == 0 {
		ws = append(ws, Warning{
			path: ".update_retention",
			msg:  "update garbage collection is off",
		})
	}
	if m.MaxConnPool != 0 {
		ws = append(ws, Warning{
			path: ".max_conn_pool",
			msg:  "this parameter will be ignored in a future release",
		})
	}

	return ws, nil
}
