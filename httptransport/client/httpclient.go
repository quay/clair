package client

import (
	"context"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"

	"github.com/quay/claircore/libvuln/driver"
)

// UoCache caches an UpdateOperation map when the server provides a conditional
// response.
type uoCache struct {
	sync.RWMutex
	uo        map[string][]driver.UpdateOperation
	validator string
}

// Set persists the update operations map and its associated validator string
// used in conditional requests.
//
// It is safe for concurrent use.
func (c *uoCache) Set(m map[string][]driver.UpdateOperation, v string) {
	c.Lock()
	defer c.Unlock()
	c.uo = m
	c.validator = v
}

// Copy returns a copy of the cache contents to the caller.
//
// It is safe for concurrent use.
func (c *uoCache) Copy() map[string][]driver.UpdateOperation {
	m := map[string][]driver.UpdateOperation{}
	c.RLock()
	defer c.RUnlock()
	for u, ops := range c.uo {
		o := make([]driver.UpdateOperation, len(ops))
		copy(o, ops)
		m[u] = o
	}
	return m
}

func newOUCache() *uoCache {
	return &uoCache{
		RWMutex: sync.RWMutex{},
	}
}

// HTTP implements access to clair interfaces over HTTP
type HTTP struct {
	diffValidator atomic.Value
	addr          *url.URL
	c             *http.Client
	uoCache       *uoCache
	uoLatestCache *uoCache
	signer        Signer
}

// DefaultAddr is used if the WithAddr Option isn't provided to New.
//
// This uses the default service port, and should just work if a containerized
// deployment has a service configured that hairpins and routes correctly.
const DefaultAddr = `http://clair:6060/`

// NewHTTP is a constructor for an HTTP client.
func NewHTTP(ctx context.Context, opt ...Option) (*HTTP, error) {
	addr, err := url.Parse(DefaultAddr)
	if err != nil {
		panic("programmer error") // Why didn't the DefaultAddr parse?
	}

	c := &HTTP{
		addr:          addr,
		c:             http.DefaultClient,
		uoCache:       newOUCache(),
		uoLatestCache: newOUCache(),
	}
	c.diffValidator.Store("")

	for _, o := range opt {
		if err := o(c); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// Option sets an option on an HTTP.
type Option func(*HTTP) error

// WithAddr sets the address to talk to.
//
// The client doesn't support providing multiple addresses, so the provided
// address should most likely have some form of load balancing or routing.
//
// The provided URL should not include the `/api/v1` prefix.
func WithAddr(root string) Option {
	u, err := url.Parse(root)
	return func(s *HTTP) error {
		if err != nil {
			return err
		}
		s.addr = u
		return nil
	}
}

// WithClient sets the http.Client used for requests.
//
// If WithClient is not supplied to NewHTTP, http.DefaultClient is used.
func WithClient(c *http.Client) Option {
	return func(s *HTTP) error {
		s.c = c
		return nil
	}
}

func WithSigner(v Signer) Option {
	return func(s *HTTP) error {
		s.signer = v
		return nil
	}
}

type Signer interface {
	Sign(context.Context, *http.Request) error
}

func (s *HTTP) sign(ctx context.Context, req *http.Request) error {
	if s.signer == nil {
		return nil
	}
	return s.signer.Sign(ctx, req)
}
