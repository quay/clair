package config_test

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/quay/clair/config"
)

type ValidateTestcase struct {
	Name  string
	Check func(*testing.T, *config.Config, error)
	Conf  config.Config
}

func (tc ValidateTestcase) Run(t *testing.T) {
	ws, err := config.Validate(&tc.Conf)
	for _, w := range ws {
		t.Logf("lint: %v", &w)
	}
	if tc.Check != nil {
		tc.Check(t, &tc.Conf, err)
	} else {
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	}
}

// This test looks a little sprawling, but it's structured by the field name
// into subtests, with the leaf test being the element triggering the failure.
//
// Doing this means the go test "run" flag is much easier to use.
func TestValidateFailure(t *testing.T) {
	shouldFail := func(t *testing.T, _ *config.Config, err error) {
		if err == nil {
			t.Error("unexpected success")
		}
	}

	// Tests on the base Config struct.
	tt := []ValidateTestcase{
		{
			Name: "InvalidMode",
			Conf: config.Config{
				Mode: config.Mode(-1),
			},
			Check: shouldFail,
		},
		{
			Name: "MalformedListenAddr",
			Conf: config.Config{
				Mode:           config.ComboMode,
				HTTPListenAddr: "xyz",
			},
			Check: shouldFail,
		},
	}
	for _, tc := range tt {
		t.Run(tc.Name, tc.Run)
	}

	t.Run("Matcher", func(t *testing.T) {
		tt := []ValidateTestcase{
			{
				Name: "IndexerAddr",
				Conf: config.Config{
					Mode:           config.MatcherMode,
					HTTPListenAddr: "localhost:8080",
					Matcher: config.Matcher{
						IndexerAddr: "",
					},
				},
				Check: shouldFail,
			},
		}
		for _, tc := range tt {
			t.Run(tc.Name, tc.Run)
		}
	})

	t.Run("Auth", func(t *testing.T) {
		tt := []ValidateTestcase{
			{
				Name: "BadPSKKey",
				Conf: config.Config{
					Mode: config.IndexerMode,
					Auth: config.Auth{
						PSK: &config.AuthPSK{},
					},
				},
				Check: shouldFail,
			},
			{
				Name: "BadPSKIssuer",
				Conf: config.Config{
					Mode: config.IndexerMode,
					Auth: config.Auth{
						PSK: &config.AuthPSK{
							Key: config.Base64([]byte{0xde, 0xad, 0xbe, 0xef}),
						},
					},
				},
				Check: shouldFail,
			},
		}
		for _, tc := range tt {
			t.Run(tc.Name, tc.Run)
		}
	})

	t.Run("Notifier", func(t *testing.T) {
		tt := []ValidateTestcase{
			{
				Name: "Multiple",
				Conf: config.Config{
					Mode: config.NotifierMode,
					Notifier: config.Notifier{
						AMQP:    &config.AMQP{},
						STOMP:   &config.STOMP{},
						Webhook: &config.Webhook{},
					},
				},
				Check: shouldFail,
			},
		}
		for _, tc := range tt {
			t.Run(tc.Name, tc.Run)
		}

		t.Run("Webhook", func(t *testing.T) {
			tt := []ValidateTestcase{
				{
					Name: "Target",
					Conf: config.Config{
						Mode: config.NotifierMode,
						Notifier: config.Notifier{
							IndexerAddr: "http://example.com/",
							MatcherAddr: "http://example.com/",
							Webhook: &config.Webhook{
								Target: " http://example.com/",
							},
						},
					},
					Check: shouldFail,
				},
				{
					Name: "Callback",
					Conf: config.Config{
						Mode: config.NotifierMode,
						Notifier: config.Notifier{
							IndexerAddr: "http://example.com/",
							MatcherAddr: "http://example.com/",
							Webhook: &config.Webhook{
								Callback: " http://example.com/",
							},
						},
					},
					Check: shouldFail,
				},
			}
			for _, tc := range tt {
				t.Run(tc.Name, tc.Run)
			}
		})

		t.Run("AMQP", func(t *testing.T) {
			tt := []ValidateTestcase{
				{
					Name: "RoutingKey",
					Conf: config.Config{
						Mode: config.NotifierMode,
						Notifier: config.Notifier{
							IndexerAddr: "http://example.com/",
							MatcherAddr: "http://example.com/",
							AMQP:        &config.AMQP{},
						},
					},
					Check: shouldFail,
				},
				{
					Name: "URIs",
					Conf: config.Config{
						Mode: config.NotifierMode,
						Notifier: config.Notifier{
							IndexerAddr: "http://example.com/",
							MatcherAddr: "http://example.com/",
							AMQP: &config.AMQP{
								RoutingKey: "test",
							},
						},
					},
					Check: shouldFail,
				},
				{
					Name: "InvalidURI",
					Conf: config.Config{
						Mode: config.NotifierMode,
						Notifier: config.Notifier{
							IndexerAddr: "http://example.com/",
							MatcherAddr: "http://example.com/",
							AMQP: &config.AMQP{
								RoutingKey: "test",
								URIs:       []string{" amqp://"},
							},
						},
					},
					Check: shouldFail,
				},
				{
					Name: "Callback",
					Conf: config.Config{
						Mode: config.NotifierMode,
						Notifier: config.Notifier{
							IndexerAddr: "http://example.com/",
							MatcherAddr: "http://example.com/",
							AMQP: &config.AMQP{
								RoutingKey: "test",
								URIs:       []string{"amqp://"},
								Callback:   " http://example.com",
							},
						},
					},
					Check: shouldFail,
				},
			}
			for _, tc := range tt {
				t.Run(tc.Name, tc.Run)
			}
		})

		t.Run("STOMP", func(t *testing.T) {
			tt := []ValidateTestcase{
				{
					Name: "URIs",
					Conf: config.Config{
						Mode: config.NotifierMode,
						Notifier: config.Notifier{
							IndexerAddr: "http://example.com/",
							MatcherAddr: "http://example.com/",
							STOMP:       &config.STOMP{},
						},
					},
					Check: shouldFail,
				},
				{
					Name: "InvalidURI",
					Conf: config.Config{
						Mode: config.NotifierMode,
						Notifier: config.Notifier{
							IndexerAddr: "http://example.com/",
							MatcherAddr: "http://example.com/",
							STOMP: &config.STOMP{
								URIs: []string{"::42"},
							},
						},
					},
					Check: shouldFail,
				},
				{
					Name: "Callback",
					Conf: config.Config{
						Mode: config.NotifierMode,
						Notifier: config.Notifier{
							IndexerAddr: "http://example.com/",
							MatcherAddr: "http://example.com/",
							STOMP: &config.STOMP{
								URIs:     []string{"stomp:567"},
								Callback: " http://example.com",
							},
						},
					},
					Check: shouldFail,
				},
			}
			for _, tc := range tt {
				t.Run(tc.Name, tc.Run)
			}

			t.Run("TLS", func(t *testing.T) {
				tt := []ValidateTestcase{
					{
						Name: "Key",
						Conf: config.Config{
							Mode: config.NotifierMode,
							Notifier: config.Notifier{
								IndexerAddr: "http://example.com/",
								MatcherAddr: "http://example.com/",
								STOMP: &config.STOMP{
									URIs:     []string{"stomp:567"},
									Callback: "http://example.com/",
									TLS: &config.TLS{
										Cert: "fail.crt",
									},
								},
							},
						},
						Check: shouldFail,
					},
					{
						Name: "Cert",
						Conf: config.Config{
							Mode: config.NotifierMode,
							Notifier: config.Notifier{
								IndexerAddr: "http://example.com/",
								MatcherAddr: "http://example.com/",
								STOMP: &config.STOMP{
									URIs:     []string{"stomp:567"},
									Callback: "http://example.com/",
									TLS: &config.TLS{
										Key: "fail.key",
									},
								},
							},
						},
						Check: shouldFail,
					},
					{
						Name: "RootCA",
						Conf: config.Config{
							Mode: config.NotifierMode,
							Notifier: config.Notifier{
								IndexerAddr: "http://example.com/",
								MatcherAddr: "http://example.com/",
								STOMP: &config.STOMP{
									URIs:     []string{"stomp:567"},
									Callback: "http://example.com/",
									TLS: &config.TLS{
										RootCA: "fail.pem",
									},
								},
							},
						},
						Check: shouldFail,
					},
				}
				for _, tc := range tt {
					t.Run(tc.Name, tc.Run)
				}
			})
		})
	})
}

func TestUpdateRetention(t *testing.T) {
	expect := func(n int) func(*testing.T, *config.Config, error) {
		return func(t *testing.T, c *config.Config, err error) {
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if got, want := c.Matcher.UpdateRetention, n; got != want {
				t.Errorf("got: %d, want: %d", got, want)
			}
		}
	}

	// Construct a bunch of test cases from (in, out) pairs.
	tt := func(p [][2]int) (tt []ValidateTestcase) {
		for _, p := range p {
			tt = append(tt, ValidateTestcase{
				Name: fmt.Sprintf("%d", p[0]),
				Conf: config.Config{
					Mode:           config.ComboMode,
					HTTPListenAddr: "localhost:8080",
					Matcher: config.Matcher{
						UpdateRetention: p[0],
					},
				},
				Check: expect(p[1]),
			})
		}
		return
	}([][2]int{
		{-1, 0},
		{0, config.DefaultUpdateRetention},
		{1, config.DefaultUpdateRetention},
		{2, 2},
	})
	for _, tc := range tt {
		t.Run(tc.Name, tc.Run)
	}
}

func TestDisableUpdaters(t *testing.T) {
	setsEmpty := func(t *testing.T, c *config.Config, err error) {
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if !cmp.Equal(c.Updaters.Sets, []string{}) {
			t.Error(cmp.Diff(c.Updaters.Sets, []string{}))
		}
	}
	tt := []ValidateTestcase{
		{
			Name: "ComboMode",
			Conf: config.Config{
				Mode: config.ComboMode,
				Matcher: config.Matcher{
					DisableUpdaters: true,
				},
				Updaters: config.Updaters{
					Sets: []string{"alpine", "aws"},
				},
			},
			Check: setsEmpty,
		},
		{
			Name: "MatcherMode",
			Conf: config.Config{
				Mode: config.MatcherMode,
				Matcher: config.Matcher{
					IndexerAddr:     "http://example.com/",
					DisableUpdaters: true,
				},
				Updaters: config.Updaters{
					Sets: []string{"alpine", "aws"},
				},
			},
			Check: setsEmpty,
		},
	}

	for _, tc := range tt {
		t.Run(tc.Name, tc.Run)
	}
}
