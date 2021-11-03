package config_test

import (
	"log"
	"testing"

	"github.com/google/go-cmp/cmp"
	"gopkg.in/yaml.v3"

	"github.com/quay/clair/v4/config"
)

func Test_Config_Validate_Failure(t *testing.T) {
	var table = []struct {
		name string
		conf config.Config
	}{
		{
			name: "No Mode",
			conf: config.Config{
				Mode: "",
			},
		},
		{
			name: "ComboMode, Malformed Global HTTP Listen Addr",
			conf: config.Config{
				Mode:           config.ComboMode,
				HTTPListenAddr: "xyz",
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
			if err := config.Validate(&tab.conf); err == nil {
				log.Fatalf("expected error for test case: %s", tab.name)
			}
		})
	}
}

func TestConfigUpdateRetention(t *testing.T) {
	var table = []struct {
		name              string
		conf              config.Config
		expectedRetention int
	}{
		{
			name:              "Retention less than 0",
			expectedRetention: 0,
			conf: config.Config{
				Mode:           config.ComboMode,
				HTTPListenAddr: "localhost:8080",
				Indexer: config.Indexer{
					ConnString: "example@example/db",
				},
				Notifier: config.Notifier{
					ConnString: "example@example/db",
				},
				Matcher: config.Matcher{
					ConnString:      "example@example/db",
					IndexerAddr:     "example@example/db",
					UpdateRetention: -1,
				},
			},
		},
		{
			name:              "Retention of 0",
			expectedRetention: 10,
			conf: config.Config{
				Mode:           config.ComboMode,
				HTTPListenAddr: "localhost:8080",
				Indexer: config.Indexer{
					ConnString: "example@example/db",
				},
				Notifier: config.Notifier{
					ConnString: "example@example/db",
				},
				Matcher: config.Matcher{
					ConnString:      "example@example/db",
					IndexerAddr:     "example@example/db",
					UpdateRetention: 0,
				},
			},
		},
		{
			name:              "Retention less than 2",
			expectedRetention: 10,
			conf: config.Config{
				Mode:           config.ComboMode,
				HTTPListenAddr: "localhost:8080",
				Indexer: config.Indexer{
					ConnString: "example@example/db",
				},
				Notifier: config.Notifier{
					ConnString: "example@example/db",
				},
				Matcher: config.Matcher{
					ConnString:      "example@example/db",
					IndexerAddr:     "example@example/db",
					UpdateRetention: 1,
				},
			},
		},
		{
			name:              "Retention of 2",
			expectedRetention: 2,
			conf: config.Config{
				Mode:           config.ComboMode,
				HTTPListenAddr: "localhost:8080",
				Indexer: config.Indexer{
					ConnString: "example@example/db",
				},
				Notifier: config.Notifier{
					ConnString: "example@example/db",
				},
				Matcher: config.Matcher{
					ConnString:      "example@example/db",
					IndexerAddr:     "example@example/db",
					UpdateRetention: 2,
				},
			},
		},
	}
	for _, tab := range table {
		t.Run(tab.name, func(t *testing.T) {
			err := config.Validate(&tab.conf)
			if err != nil {
				log.Fatalf("expected no errors but got: %s, for test case: %s", err, tab.name)
			}
			if tab.conf.Matcher.UpdateRetention != tab.expectedRetention {
				t.Fatalf("expected UpdateRetention of %d but got %d", tab.expectedRetention, tab.conf.Matcher.UpdateRetention)
			}
		})
	}
}

func TestConfigDisableUpdaters(t *testing.T) {
	var table = []struct {
		name string
		conf config.Config
	}{
		{
			name: "ComboMode, disable updaters",
			conf: config.Config{
				Mode:           config.ComboMode,
				HTTPListenAddr: "localhost:8080",
				Indexer: config.Indexer{
					ConnString: "example@example/db",
				},
				Notifier: config.Notifier{
					ConnString: "example@example/db",
				},
				Matcher: config.Matcher{
					ConnString:      "example@example/db",
					IndexerAddr:     "example@example/db",
					DisableUpdaters: true,
				},
				Updaters: config.Updaters{
					Sets: []string{
						"alpine",
						"aws",
					},
				},
			},
		},
		{
			name: "MatcherMode, disable updaters",
			conf: config.Config{
				Mode:           config.MatcherMode,
				HTTPListenAddr: "localhost:8080",
				Matcher: config.Matcher{
					ConnString:      "example@example/db",
					IndexerAddr:     "example@example/db",
					DisableUpdaters: true,
				},
				Updaters: config.Updaters{
					Sets: []string{
						"alpine",
						"aws",
					},
				},
			},
		},
	}

	for _, tab := range table {
		t.Run(tab.name, func(t *testing.T) {
			err := config.Validate(&tab.conf)
			if err != nil {
				log.Fatalf("expected no errors but got: %s, for test case: %s", err, tab.name)
			}
			if len(tab.conf.Updaters.Sets) != 0 {
				log.Fatalf("expected updaters sets to be empty but was: %s, for test case: %s", tab.conf.Updaters.Sets, tab.name)
			}
		})
	}
}

func TestAuthUnmarshal(t *testing.T) {
	t.Run("PSK", func(t *testing.T) {
		type testcase struct {
			In   string
			Want config.AuthPSK
		}
		var tt = []testcase{
			{
				In: `---
key: >-
  ZGVhZGJlZWZkZWFkYmVlZg==
iss: 
  - iss
`,
				Want: config.AuthPSK{
					Key:    []byte("deadbeefdeadbeef"),
					Issuer: []string{"iss"},
				},
			},
		}

		check := func(t *testing.T, tc testcase) {
			v := config.AuthPSK{}
			if err := yaml.Unmarshal([]byte(tc.In), &v); err != nil {
				t.Error(err)
			}
			if got, want := v, tc.Want; !cmp.Equal(got, want) {
				t.Error(cmp.Diff(got, want))
			}
		}
		for _, tc := range tt {
			check(t, tc)
		}
	})

	t.Run("Keyserver", func(t *testing.T) {
		type testcase struct {
			In   string
			Want config.AuthKeyserver
		}
		var tt = []testcase{
			{
				In: `---
api: quay/keys
intraservice: >-
  ZGVhZGJlZWZkZWFkYmVlZg==
`,
				Want: config.AuthKeyserver{
					API:          "quay/keys",
					Intraservice: []byte("deadbeefdeadbeef"),
				},
			},
		}

		check := func(t *testing.T, tc testcase) {
			v := config.AuthKeyserver{}
			if err := yaml.Unmarshal([]byte(tc.In), &v); err != nil {
				t.Error(err)
			}
			if got, want := v, tc.Want; !cmp.Equal(got, want) {
				t.Error(cmp.Diff(got, want))
			}
		}
		for _, tc := range tt {
			check(t, tc)
		}
	})
}
