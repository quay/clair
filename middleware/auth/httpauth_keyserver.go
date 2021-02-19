package auth

import (
	"context"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/gregjones/httpcache"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"

	"github.com/quay/clair/v4/internal/codec"
)

// QuayKeyserver implements the AuthCheck interface.
//
// When Check is called the JWT on the incoming http request
// will be validated against the Quay Keyserver
//
// It follows the algorithm outlined here:
// https://github.com/quay/jwtproxy/tree/master/jwt/keyserver/keyregistry#verifier
type QuayKeyserver struct {
	root   *url.URL
	client *http.Client
	mu     sync.RWMutex
	cache  map[string]*jose.JSONWebKey
}

// NewQuayKeyserver returns an instance of a QuayKeyserver
func NewQuayKeyserver(api string) (*QuayKeyserver, error) {
	root, err := url.Parse(api)
	if err != nil {
		return nil, err
	}

	t := httpcache.NewMemoryCacheTransport()
	t.MarkCachedResponses = true
	return &QuayKeyserver{
		client: t.Client(),
		root:   root,
		cache:  make(map[string]*jose.JSONWebKey),
	}, nil
}

// AlgoAllow is an allowlist of signature algorithms.
//
// The jose package doesn't allow the mistake of putting "none" in this list,
// but otherwise this is similar to the list of algorithms Quay maintains.
var algoAllow = []string{
	string(jose.RS256),
}

// Check implements AuthCheck.
func (s *QuayKeyserver) Check(ctx context.Context, r *http.Request) bool {
	wt, ok := fromHeader(r)
	if !ok {
		return false
	}
	tok, err := jwt.ParseSigned(wt)
	if err != nil {
		return false
	}

	// Need to find the key id.
	ok = false
	var kid string
HeaderSearch:
	for _, h := range tok.Headers {
		for _, a := range algoAllow {
			if h.Algorithm == a {
				ok = true
				kid = h.KeyID
				break HeaderSearch
			}
		}
	}
	if !ok {
		return false
	}
	// Need to pull out the issuer to fetch the key. We cannot return "true"
	// until *after* a safe Claims call succeeds.
	cl := jwt.Claims{}
	if err := tok.UnsafeClaimsWithoutVerification(&cl); err != nil {
		return false
	}
	uri, err := s.root.Parse(path.Join("./", "services", cl.Issuer, "keys", kid))
	if err != nil {
		return false
	}
	ck := cl.Issuer + "+" + kid

	// This request will be cached according to the cache-control headers.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "", nil)
	if err != nil {
		return false
	}
	req.URL = uri
	res, err := s.client.Do(req)
	if err != nil {
		return false
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		// If the keyserver returns a non-OK, we can't use the key: it doesn't
		// exist or is expired or is not yet approved, so make sure to delete it
		// from our cache. Delete is a no-op if we don't have the key.
		s.mu.Lock()
		delete(s.cache, ck)
		s.mu.Unlock()
		return false
	}
	s.mu.RLock()
	jwk, ok := s.cache[ck]
	s.mu.RUnlock()
	// If not in our deserialized cache or our response has been served from the
	// remote server, do the deserializtion and cache it.
	if !ok || res.Header.Get(httpcache.XFromCache) != "" {
		jwk = &jose.JSONWebKey{}
		dec := codec.GetDecoder(res.Body)
		defer codec.PutDecoder(dec)
		if err := dec.Decode(jwk); err != nil {
			return false
		}
		s.mu.Lock()
		// Only store if we didn't get beaten by another request.
		if _, ok := s.cache[ck]; !ok {
			s.cache[ck] = jwk
		}
		s.mu.Unlock()
	}

	if err := tok.Claims(jwk.Key, &cl); err != nil {
		return false
	}
	// Returning true is now possible.
	if err := cl.ValidateWithLeeway(jwt.Expected{
		Audience: findAudience(r),
		Time:     time.Now(),
	}, 15*time.Second); err != nil {
		return false
	}
	return true
}

// FindAudience looks at a variety of information to guess a valid audience.
func findAudience(r *http.Request) (ret jwt.Audience) {
	// Prefer the new, standardized header.
	//
	// One would hope modern proxies are adding these headers at every hop.
	if fwds, ok := r.Header["Forwarded"]; ok {
	Fwd:
		for _, fwd := range fwds {
			fwd := strings.TrimSpace(fwd)
			proto, host := "http", ""
			for _, kv := range strings.Split(fwd, ";") {
				i := strings.IndexByte(kv, '=')
				if i == -1 {
					// If there's a key without a "=", this header is a botch;
					// skip it.
					continue Fwd
				}
				k := kv[:i]
				v := kv[i+1:]
				switch k {
				case "host":
					host = v
				case "proto":
					proto = v
				}
			}
			if host != "" && proto != "" {
				ret = append(ret, proto+"://"+host)
			}
		}
	}
	if len(ret) != 0 {
		return
	}

	// Fall back to the nonstandard headers.
	//
	// Reverse proxies are probably setting these, and hopefully only the first
	// one.
	xfp := r.Header.Get("x-forwarded-proto")
	if xfp == "" {
		xfp = "http"
	}
	if h := r.Header.Get("x-forwarded-host"); h != "" {
		ret = append(ret, xfp+"://"+h)
	}
	if len(ret) != 0 {
		return
	}

	// Finally, use the requested URL.
	//
	// This will be wrong except in trivial configurations.
	u, err := r.URL.Parse("/")
	if err == nil {
		ret = append(ret, strings.TrimSuffix(u.String(), "/"))
	}
	return
}
