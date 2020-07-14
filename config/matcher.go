package config

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
	// A slice of strings representing which
	// updaters matcher will create.
	//
	// If nil all default UpdaterSets will be used
	//
	// The following sets are supported:
	// "alpine"
	// "aws"
	// "debian"
	// "oracle"
	// "photon"
	// "pyupio"
	// "rhel"
	// "suse"
	// "ubuntu"
	UpdaterSets []string `yaml:"updater_sets" json:"updater_sets"`
}
