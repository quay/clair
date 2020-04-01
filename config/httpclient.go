package config

import (
	"net/http"
	"time"

	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

// Client returns an http.Client configured according to the supplied
// configuration.
//
// It returns an *http.Client and a boolean indicating whether the client is
// configured for authentication, or an error that occurred during construction.
func (cfg *Config) Client(next *http.Transport) (c *http.Client, authed bool, err error) {
	authed = false
	sk := jose.SigningKey{Algorithm: jose.HS256}

	// Keep this organized from "best" to "worst". That way, we can add methods
	// and keep everything working with some careful cluster rolling.
	switch {
	case cfg.Auth.Keyserver != nil:
		sk.Key = cfg.Auth.Keyserver.Intraservice
	case cfg.Auth.PSK != nil:
		sk.Key = cfg.Auth.PSK.Key
	default:
	}
	rt := &transport{next: next}
	c = &http.Client{Transport: rt}

	// Both of the JWT-based methods set the signing key.
	if sk.Key != nil {
		signer, err := jose.NewSigner(sk, nil)
		if err != nil {
			return nil, false, err
		}
		rt.Signer = signer
		authed = true
	}
	return c, authed, nil
}

var _ http.RoundTripper = (*transport)(nil)

// Transport does request modification common to all requests.
type transport struct {
	jose.Signer
	next http.RoundTripper
}

func (cs *transport) RoundTrip(r *http.Request) (*http.Response, error) {
	const (
		issuer    = `clair-intraservice`
		userAgent = `clair/v4`
	)
	r.Header.Set("user-agent", userAgent)
	if cs.Signer != nil {
		// TODO(hank) Make this mint longer-lived tokens and re-use them, only
		// refreshing when needed. Like a resettable sync.Once.
		now := time.Now()
		cl := jwt.Claims{
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now.Add(-jwt.DefaultLeeway)),
			Expiry:    jwt.NewNumericDate(now.Add(jwt.DefaultLeeway)),
			Issuer:    issuer,
		}
		h, err := jwt.Signed(cs).Claims(&cl).CompactSerialize()
		if err != nil {
			return nil, err
		}
		r.Header.Add("authorization", "Bearer "+h)
	}
	return cs.next.RoundTrip(r)
}
