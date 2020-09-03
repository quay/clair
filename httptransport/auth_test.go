package httptransport

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/quay/clair/v4/config"
)

type authTestcase struct {
	Name       string
	Config     config.Config
	ShouldFail bool
	ConfigMod  func(*testing.T, *config.Config)
}

func (tc *authTestcase) Run(t *testing.T) {
	// Generate a nonce to return upon request.
	b := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		t.Fatal(err)
	}
	nonce := hex.EncodeToString(b)

	// Return the nonce when called.
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a := r.Header.Get("authorization"); a != "" {
			t.Logf("Authorization: %s", a)
		}
		fmt.Fprint(w, nonce)
	})

	// Create a handler that has auth according to the config.
	h, err := authHandler(&tc.Config, next)
	if err != nil {
		t.Error(err)
	}

	// Wire up the handler to a test server.
	srv := httptest.NewServer(h)
	defer srv.Close()

	// Modify the config, if present
	if f := tc.ConfigMod; f != nil {
		f(t, &tc.Config)
	}

	// Create a client that has auth according to the config.
	c, authed, err := tc.Config.Client(nil)
	if err != nil {
		t.Error(err)
	}
	t.Logf("authed: %v", authed)

	// Make the request.
	res, err := c.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	wantStatus := http.StatusOK
	if tc.ShouldFail {
		wantStatus = http.StatusUnauthorized
	}
	t.Logf("status code: %v", res.StatusCode)
	if res.StatusCode != wantStatus {
		t.Fail()
	}
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, res.Body); err != nil {
		t.Error(err)
	}

	// Compare the nonce.
	got, want := buf.String(), nonce
	t.Logf("http request, got: %q want: %q", got, want)
	if got != want && !tc.ShouldFail {
		t.Fail()
	}
}

// TestAuth tests configuring both http server and client.
func TestAuth(t *testing.T) {
	var fakeKey = []byte("deadbeef")
	tt := []authTestcase{
		{Name: "None"},
		{
			Name: "PSK",
			Config: config.Config{
				Auth: config.Auth{
					PSK: &config.AuthPSK{
						Issuer: `sweet-bro`,
						Key:    fakeKey,
					},
				},
			},
		},
		{
			Name: "FakeKeyserver",
			Config: config.Config{
				Auth: config.Auth{
					Keyserver: &config.AuthKeyserver{
						API:          "http://localhost",
						Intraservice: fakeKey,
					},
				},
			},
		},
		{
			Name: "PSKBadKey",
			Config: config.Config{
				Auth: config.Auth{
					PSK: &config.AuthPSK{
						Issuer: `sweet-bro`,
						Key:    fakeKey,
					},
				},
			},
			ShouldFail: true,
			ConfigMod:  func(t *testing.T, cfg *config.Config) { cfg.Auth.PSK.Key = []byte("badbeef") },
		},
		{
			Name: "FakeKeyserverFail",
			Config: config.Config{
				Auth: config.Auth{
					Keyserver: &config.AuthKeyserver{
						API:          "http://localhost",
						Intraservice: fakeKey,
					},
				},
			},
			ShouldFail: true,
			ConfigMod:  func(t *testing.T, cfg *config.Config) { cfg.Auth.Keyserver = nil },
		},
		{
			Name: "PSKFail",
			Config: config.Config{
				Auth: config.Auth{
					PSK: &config.AuthPSK{
						Issuer: `sweet-bro`,
						Key:    fakeKey,
					},
				},
			},
			ShouldFail: true,
			ConfigMod:  func(t *testing.T, cfg *config.Config) { cfg.Auth.PSK = nil },
		},
	}

	for _, tc := range tt {
		t.Run(tc.Name, tc.Run)
	}
}
