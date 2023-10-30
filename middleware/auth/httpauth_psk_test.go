package auth

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"testing/quick"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"

	"github.com/quay/clair/v4/internal/httputil"
)

type pskTestcase struct {
	key    []byte
	issuer []string
	nonce  string
	alg    jose.SignatureAlgorithm
}

func (tc *pskTestcase) String() string {
	return fmt.Sprintf("\nalg:\t%s\nkey:\t%x\nissuer:\t%s\nnonce:\t%s",
		tc.alg, tc.key, tc.issuer, tc.nonce)
}

var signAlgo = []jose.SignatureAlgorithm{
	jose.HS256,
	jose.HS384,
	jose.HS512,
}

// implements the Generate interface from testing/quick package.
func (tc *pskTestcase) Generate(rand *rand.Rand, sz int) reflect.Value {
	b := make([]byte, sz)
	t := &pskTestcase{
		key:    make([]byte, sz),
		alg:    signAlgo[rand.Intn(len(signAlgo))],
		issuer: make([]string, 0),
	}
	switch n, err := rand.Read(t.key); {
	case n != sz:
		panic(fmt.Errorf("read %d, expected %d", n, sz))
	case err != nil:
		panic(err)
	}

	switch n, err := rand.Read(b); {
	case n != sz:
		panic(fmt.Errorf("read %d, expected %d", n, sz))
	case err != nil:
		panic(err)
	default:
		t.issuer = append(t.issuer, base64.StdEncoding.EncodeToString(b))
	}

	switch n, err := rand.Read(b); {
	case n != sz:
		panic(fmt.Errorf("read %d, expected %d", n, sz))
	case err != nil:
		panic(err)
	default:
		t.nonce = base64.StdEncoding.EncodeToString(b)
	}

	return reflect.ValueOf(t)
}

func (tc *pskTestcase) Handler(t *testing.T) http.Handler {
	af, err := NewPSK(tc.key, tc.issuer)
	if err != nil {
		t.Error(err)
		return nil
	}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ah := strings.TrimPrefix(r.Header.Get("authorization"), "Bearer ")
		t.Logf("got jwt: %s", ah)
		fmt.Fprint(w, tc.nonce)
	})
	return Handler(h, af)
}

// Roundtrips returns a function suitable for passing to quick.Check.
func roundtrips(t *testing.T) func(*pskTestcase) bool {
	return func(tc *pskTestcase) bool {
		ctx := context.Background()
		t.Log(tc)
		// Set up the jwt signer.
		sk := jose.SigningKey{
			Algorithm: tc.alg,
			Key:       tc.key,
		}
		s, err := jose.NewSigner(sk, nil)
		if err != nil {
			t.Error(err)
			return false
		}
		now := time.Now()

		// Mint the jwt.
		tok, err := jwt.Signed(s).Claims(&jwt.Claims{
			Issuer:    tc.issuer[0],
			Expiry:    jwt.NewNumericDate(now.Add(time.Minute)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
		}).CompactSerialize()
		if err != nil {
			t.Error(err)
			return false
		}

		// Set up the http server.
		h := tc.Handler(t)
		if t.Failed() {
			return false
		}
		srv := httptest.NewServer(h)
		defer srv.Close()

		// Mint a request.
		req, err := httputil.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
		if err != nil {
			t.Error(err)
			return false
		}
		req.Header.Set("authorization", "Bearer "+tok)

		// Execute the request and read back the body.
		res, err := srv.Client().Do(req)
		if err != nil {
			t.Error(err)
			return false
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Error(fmt.Errorf("unexpected response: %d %s", res.StatusCode, res.Status))
			return false
		}
		buf := &bytes.Buffer{}
		if _, err := buf.ReadFrom(res.Body); err != nil {
			t.Error(err)
			return false
		}

		// Compare the body read to the nonce we were expecting.
		t.Logf("\nread:\t%s", buf.String())
		if got, want := buf.String(), tc.nonce; got != want {
			t.Error(fmt.Errorf("got: %q, want: %q", got, want))
			return false
		}
		return true
	}
}

// TestPSKAuth generates random keys and checks signing with it.
func TestPSKAuth(t *testing.T) {
	t.Parallel()
	// Generate random keys and check them via the roundtrips function.
	cfg := quick.Config{}
	if err := quick.Check(roundtrips(t), &cfg); err != nil {
		t.Fatal(err)
	}
}
