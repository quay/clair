package config_test

import (
	"log"
	"testing"

	"github.com/quay/clair/v4/config"
)

func Test_Config_Validate_Failure(t *testing.T) {
	var table = []struct {
		name   string
		conf   config.Config
		expect bool
	}{
		{
			name: "No Mode",
			conf: config.Config{
				Mode: "",
			},
		},
		// A mode must be defined in the conf file
		{
			name: "DevMode, No Global HTTP Listen Addr",
			conf: config.Config{
				Mode:           config.DevMode,
				HTTPListenAddr: "",
			},
		},
		// DevMode requires a global http listen addr in order for
		// all services to listen on one address:port tuple
		{
			name: "DevMode, Malformed Global HTTP Listen Addr",
			conf: config.Config{
				Mode:           config.DevMode,
				HTTPListenAddr: "xyz",
			},
		},
		{
			name: "DevMode, Malformed Global HTTP Listen Addr",
			conf: config.Config{
				Mode:           config.DevMode,
				HTTPListenAddr: "xyz",
			},
		},
		// Indexer and Matcher modes require both a listen http addr and a database connection string
		// other fields will use defaults defined in claircore. Matcher mode requires an address to a remote Indexer.
		{
			name: "IndexerMode, No HTTPListenAddr",
			conf: config.Config{
				Mode: config.IndexerMode,
				Indexer: config.Indexer{
					HTTPListenAddr: "",
					ConnString:     "example@exampl/db",
				},
			},
		},
		{
			name: "IndexerMode, No ConnString",
			conf: config.Config{
				Mode: config.IndexerMode,
				Indexer: config.Indexer{
					HTTPListenAddr: "localhost:8080",
					ConnString:     "",
				},
			},
		},
		{
			name: "MatcherMode, No HTTPListenAddr",
			conf: config.Config{
				Mode: config.MatcherMode,
				Matcher: config.Matcher{
					HTTPListenAddr: "",
					ConnString:     "example@exampl/db",
				},
			},
		},
		{
			name: "MatcherMode, No ConnString",
			conf: config.Config{
				Mode: config.MatcherMode,
				Matcher: config.Matcher{
					HTTPListenAddr: "localhost:8080",
					ConnString:     "",
				},
			},
		},
		{
			name: "MatcherMode, No IndexerAddr",
			conf: config.Config{
				Mode: config.MatcherMode,
				Matcher: config.Matcher{
					HTTPListenAddr: "localhost:8080",
					ConnString:     "example@example/db",
					IndexerAddr:    "",
				},
			},
		},
	}

	for _, tab := range table {
		t.Run(tab.name, func(t *testing.T) {
			if err := config.Validate(tab.conf); err == nil {
				log.Fatalf("expected error for test case: %s", tab.name)
			}
		})
	}
}
