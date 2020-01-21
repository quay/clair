package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"testing/quick"
	"time"

	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

type pskTestcase struct {
	key    []byte
	issuer string
	nonce  string
	alg    jose.SignatureAlgorithm
}

func (tc *pskTestcase) String() string {
	return fmt.Sprintf("\nkey:\t%x\nissuer:\t%s\nnonce:\t%s", tc.key, tc.issuer, tc.nonce)
}

var signAlgo = []jose.SignatureAlgorithm{
	jose.EdDSA,
	jose.HS256,
	jose.HS384,
	jose.HS512,
	jose.RS256,
	jose.RS384,
	jose.RS512,
	jose.ES256,
	jose.ES384,
	jose.ES512,
	jose.PS256,
	jose.PS384,
	jose.PS512,
}

func (tc *pskTestcase) Generate(rand *rand.Rand, sz int) reflect.Value {
	b := make([]byte, sz)
	n := &pskTestcase{
		key: make([]byte, sz),
		alg: signAlgo[rand.Intn(len(signAlgo))],
	}
	switch n, err := rand.Read(n.key); {
	case n != sz:
		panic(fmt.Errorf("read %d, expected %d", n, sz))
	case err != nil:
		panic(err)
	}

	for _, t := range []*string{
		&n.issuer,
		&n.nonce,
	} {
		switch n, err := rand.Read(b); {
		case n != sz:
			panic(fmt.Errorf("read %d, expected %d", n, sz))
		case err != nil:
			panic(err)
		}
		*t = base64.StdEncoding.EncodeToString(b)
	}

	return reflect.ValueOf(n)
}

func (tc *pskTestcase) Handler() (http.Handler, error) {
	af, err := PSKAuth(tc.key, tc.issuer)
	if err != nil {
		return nil, err
	}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, tc.nonce)
	})
	return AuthHandler(h, af), nil
}

// Roundtrips returns a function suitable for passing to quick.Check.
func roundtrips(t *testing.T) func(*pskTestcase) bool {
	return func(tc *pskTestcase) bool {
		t.Log(tc)
		// Set up the jwt signer.
		sk := jose.SigningKey{
			Algorithm: jose.HS256,
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
			Issuer:    tc.issuer,
			Expiry:    jwt.NewNumericDate(now.Add(time.Minute)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
		}).CompactSerialize()
		if err != nil {
			t.Error(err)
			return false
		}

		// Set up the http server.
		h, err := tc.Handler()
		if err != nil {
			t.Error(err)
			return false
		}
		srv := httptest.NewServer(h)
		defer srv.Close()

		// Mint a request.
		req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
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
