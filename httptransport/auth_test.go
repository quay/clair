package httptransport

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/quay/zlog"
	"gopkg.in/square/go-jose.v2/jwt"

	"github.com/quay/clair/v4/config"
	"github.com/quay/clair/v4/internal/httputil"
)

type authTestcase struct {
	Claims     *jwt.Claims
	ConfigMod  func(*testing.T, *config.Config)
	Config     config.Config
	Name       string
	ShouldFail bool
}

var defaultClaims = jwt.Claims{
	Issuer: IntraserviceIssuer,
}

func (tc *authTestcase) Run(ctx context.Context) func(*testing.T) {
	return func(t *testing.T) {
		ctx := zlog.Test(ctx, t)
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
		srv := httptest.NewUnstartedServer(h)
		srv.Config.BaseContext = func(_ net.Listener) context.Context { return ctx }
		srv.Start()
		defer srv.Close()

		// Modify the config, if present
		if f := tc.ConfigMod; f != nil {
			f(t, &tc.Config)
		}

		// Use a default intraservice claim if not set.
		if tc.Claims == nil {
			tc.Claims = &defaultClaims
		}

		// Create a client that has auth according to the config.
		c, authed, err := httputil.Client(nil, tc.Claims, &tc.Config)
		if err != nil {
			t.Error(err)
		}
		t.Logf("authed: %v", authed)
		if c == nil {
			t.FailNow()
		}

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
}

// TestAuth tests configuring both http server and client.
func TestAuth(t *testing.T) {
	fakeKey := []byte("deadbeef")
	tt := []authTestcase{
		{Name: "None"},
		{
			Name: "PSK",
			Config: config.Config{
				Auth: config.Auth{
					PSK: &config.AuthPSK{
						Issuer: []string{`sweet-bro`},
						Key:    fakeKey,
					},
				},
			},
		},
		{
			Name: "PSKMultipleIssuer",
			Config: config.Config{
				Auth: config.Auth{
					PSK: &config.AuthPSK{
						Issuer: []string{`sweet-bro`, `hella-jeff`, `geromy`},
						Key:    fakeKey,
					},
				},
			},
			Claims: &jwt.Claims{Issuer: `geromy`},
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
						Issuer: []string{`sweet-bro`},
						Key:    fakeKey,
					},
				},
			},
			ShouldFail: true,
			ConfigMod:  func(_ *testing.T, cfg *config.Config) { cfg.Auth.PSK.Key = []byte("badbeef") },
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
			ConfigMod:  func(_ *testing.T, cfg *config.Config) { cfg.Auth.Keyserver = nil },
		},
		{
			Name: "PSKFail",
			Config: config.Config{
				Auth: config.Auth{
					PSK: &config.AuthPSK{
						Issuer: []string{`sweet-bro`},
						Key:    fakeKey,
					},
				},
			},
			ShouldFail: true,
			ConfigMod:  func(_ *testing.T, cfg *config.Config) { cfg.Auth.PSK = nil },
		},
	}

	ctx := zlog.Test(context.Background(), t)
	for _, tc := range tt {
		t.Run(tc.Name, tc.Run(ctx))
	}
}
