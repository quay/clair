package httputil

import (
	"net/http"
	"net/http/cookiejar"
	"time"

	"golang.org/x/net/publicsuffix"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"

	"github.com/quay/clair/v4/config"
)

// Client returns an http.Client configured according to the supplied
// configuration.
//
// If nil is passed for a claim, the returned client does no signing.
//
// It returns an *http.Client and a boolean indicating whether the client is
// configured for authentication, or an error that occurred during construction.
func Client(next http.RoundTripper, cl *jwt.Claims, cfg *config.Config) (c *http.Client, authed bool, err error) {
	if next == nil {
		next = http.DefaultTransport.(*http.Transport).Clone()
	}
	authed = false
	jar, err := cookiejar.New(&cookiejar.Options{
		PublicSuffixList: publicsuffix.List,
	})
	if err != nil {
		return nil, false, err
	}
	c = &http.Client{
		Jar: jar,
	}

	sk := jose.SigningKey{Algorithm: jose.HS256}
	// Keep this organized from "best" to "worst". That way, we can add methods
	// and keep everything working with some careful cluster rolling.
	switch {
	case cl == nil: // Skip signing
	case cfg.Auth.Keyserver != nil:
		sk.Key = []byte(cfg.Auth.Keyserver.Intraservice)
	case cfg.Auth.PSK != nil:
		sk.Key = []byte(cfg.Auth.PSK.Key)
	default:
	}
	rt := &transport{
		next: next,
	}
	// If we have a claim, make a copy into the transport.
	if cl != nil {
		rt.base = *cl
	}
	c.Transport = rt

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
	base jwt.Claims
}

func (cs *transport) RoundTrip(r *http.Request) (*http.Response, error) {
	const (
		userAgent = `clair/v4`
	)
	r.Header.Set("user-agent", userAgent)
	if cs.Signer != nil {
		// TODO(hank) Make this mint longer-lived tokens and re-use them, only
		// refreshing when needed. Like a resettable sync.Once.
		now := time.Now()
		cl := cs.base
		cl.IssuedAt = jwt.NewNumericDate(now)
		cl.NotBefore = jwt.NewNumericDate(now.Add(-jwt.DefaultLeeway))
		cl.Expiry = jwt.NewNumericDate(now.Add(jwt.DefaultLeeway))
		h, err := jwt.Signed(cs).Claims(&cl).CompactSerialize()
		if err != nil {
			return nil, err
		}
		r.Header.Add("authorization", "Bearer "+h)
	}
	return cs.next.RoundTrip(r)
}
