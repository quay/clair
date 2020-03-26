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
		{
			name: "ComboMode, No Global HTTP Listen Addr",
			conf: config.Config{
				Mode:           config.ComboMode,
				HTTPListenAddr: "",
			},
		},
		{
			name: "ComboMode, Malformed Global HTTP Listen Addr",
			conf: config.Config{
				Mode:           config.ComboMode,
				HTTPListenAddr: "xyz",
			},
		},
		// Indexer and Matcher modes require both a listen http addr and a database connection string
		// other fields will use defaults defined in claircore. Matcher mode requires an address to a remote Indexer.
		{
			name: "IndexerMode, No HTTPListenAddr",
			conf: config.Config{
				Mode:           config.IndexerMode,
				HTTPListenAddr: "",
				Indexer: config.Indexer{
					ConnString: "example@example/db",
				},
			},
		},
		{
			name: "IndexerMode, No ConnString",
			conf: config.Config{
				Mode:           config.IndexerMode,
				HTTPListenAddr: "localhost:8080",
				Indexer: config.Indexer{
					ConnString: "",
				},
			},
		},
		{
			name: "MatcherMode, No HTTPListenAddr",
			conf: config.Config{
				Mode:           config.MatcherMode,
				HTTPListenAddr: "",
				Matcher: config.Matcher{
					ConnString: "example@example/db",
				},
			},
		},
		{
			name: "MatcherMode, No ConnString",
			conf: config.Config{
				Mode:           config.MatcherMode,
				HTTPListenAddr: "localhost:8080",
				Matcher: config.Matcher{
					ConnString: "",
				},
			},
		},
		{
			name: "MatcherMode, No IndexerAddr",
			conf: config.Config{
				Mode:           config.MatcherMode,
				HTTPListenAddr: "localhost:8080",
				Matcher: config.Matcher{
					ConnString:  "example@example/db",
					IndexerAddr: "",
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
