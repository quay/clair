package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/gregjones/httpcache"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

// QuayKS implements the AuthCheck interface.
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
	aud, err := r.URL.Parse("/")
	if err != nil {
		return false
	}
	// Need to find the key id.
	ok = false
	var kid string
	for _, h := range tok.Headers {
		if h.Algorithm == string(jose.RS256) {
			ok = true
			kid = h.KeyID
			break
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
	if res != nil {
		defer res.Body.Close()
	}
	if err != nil {
		return false
	}
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
		if err := json.NewDecoder(res.Body).Decode(jwk); err != nil {
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
		Audience: jwt.Audience{strings.TrimRight(aud.String(), "/")},
		Time:     time.Now(),
	}, 15*time.Second); err != nil {
		return false
	}
	return true
}
