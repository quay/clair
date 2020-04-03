package client

import (
	"context"
	"net/http"
	"net/url"
	"sync/atomic"
)

// HTTP implements access to clair interfaces over HTTP
type HTTP = *httpClient

// httpClient has this weird two-step where it's an unexported type and an
// exported alias so that we can return something that's impossible for another
// package to construct, but is still a concrete type.
//
// This has the small rub that all the methods need to be defined on the
// exported alias so they appear correctly in the documentation.
type httpClient struct {
	addr *url.URL
	c    *http.Client

	diffValidator atomic.Value
}

// DefaultAddr is used if the WithAddr Option isn't provided to New.
//
// This uses the default service port, and should just work if a containerized
// deployment has a service configured that hairpins and routes correctly.
const DefaultAddr = `http://clair:6060/`

// NewHTTP is a constructor for an HTTP client.
func NewHTTP(ctx context.Context, opt ...Option) (HTTP, error) {
	addr, err := url.Parse(DefaultAddr)
	if err != nil {
		panic("programmer error") // Why didn't the DefaultAddr parse?
	}

	c := httpClient{
		addr: addr,
		c:    http.DefaultClient,
	}
	c.diffValidator.Store("")

	for _, o := range opt {
		if err := o(&c); err != nil {
			return nil, err
		}
	}
	return &c, nil
}

// Option sets an option on an HTTP.
type Option func(HTTP) error

// WithAddr sets the address to talk to.
//
// The client doesn't support providing multiple addresses, so the provided
// address should most likely have some form of load balancing or routing.
//
// The provided URL should not include the `/api/v1` prefix.
func WithAddr(root string) Option {
	u, err := url.Parse(root)
	return func(s *httpClient) error {
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
	return func(s *httpClient) error {
		s.c = c
		return nil
	}
}
