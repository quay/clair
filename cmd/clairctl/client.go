package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"sync"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/quay/claircore"
	"github.com/tomnomnom/linkheader"

	"github.com/quay/clair/v4/httptransport"
	"github.com/quay/clair/v4/internal/codec"
)

const (
	userAgent = `clairctl/1`
)

var (
	rtMu  sync.Mutex
	rtMap = map[string]http.RoundTripper{}
)

func rt(ref string) (http.RoundTripper, error) {
	r, err := name.ParseReference(ref)
	if err != nil {
		return nil, err
	}
	repo := r.Context()
	key := repo.String()
	rtMu.Lock()
	defer rtMu.Unlock()
	if v, ok := rtMap[key]; ok {
		return v, nil
	}

	auth, err := authn.DefaultKeychain.Resolve(repo)
	if err != nil {
		return nil, err
	}
	rt, err := transport.New(repo.Registry, auth, http.DefaultTransport, []string{repo.Scope("pull")})
	if err != nil {
		return nil, err
	}
	rtMap[key] = rt
	return rt, nil
}

// TODO Maybe turn this into a real client, once it's proved useful.
type Client struct {
	host   *url.URL
	client *http.Client

	mu        sync.RWMutex
	validator map[string]string
}

func NewClient(c *http.Client, root string) (*Client, error) {
	if c == nil {
		c = http.DefaultClient
	}
	host, err := url.Parse(root)
	if err != nil {
		return nil, err
	}
	return &Client{
		host:      host,
		client:    c,
		validator: make(map[string]string),
	}, nil
}

func (c *Client) getValidator(path string) string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.validator[path]
}

func (c *Client) setValidator(path, v string) {
	debug.Printf("setting validator %q → %q", path, v)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.validator[path] = v
}

var errNeedManifest = errors.New("manifest needed but not supplied")

func (c *Client) IndexReport(ctx context.Context, id claircore.Digest, m *claircore.Manifest) error {
	var (
		req *http.Request
		res *http.Response
	)
	fp, err := c.host.Parse(path.Join(c.host.RequestURI(), httptransport.IndexReportAPIPath, id.String()))
	if err != nil {
		debug.Printf("unable to construct index_report url: %v", err)
		return err
	}
	req = c.request(ctx, fp, http.MethodGet)
	res, err = c.client.Do(req)
	if res != nil {
		// Don't actually care.
		res.Body.Close()
	}
	if err != nil {
		debug.Printf("request failed for url %q: %v", req.URL.String(), err)
		return err
	}
	debug.Printf("%s %s: %s", res.Request.Method, res.Request.URL.Path, res.Status)
	switch res.StatusCode {
	case http.StatusOK, http.StatusNotFound:
		debug.Printf("need to post manifest %v", id)
	case http.StatusNotModified:
		return nil
	default:
		return fmt.Errorf("unexpected return status: %d", res.StatusCode)
	}

	if m == nil {
		debug.Printf("don't have needed manifest %v", id)
		return errNeedManifest
	}
	ru, err := c.host.Parse(path.Join(c.host.RequestURI(), httptransport.IndexAPIPath))
	if err != nil {
		debug.Printf("unable to construct index_report url: %v", err)
		return err
	}

	req = c.request(ctx, ru, http.MethodPost)
	req.Body = codec.JSONReader(m)
	res, err = c.client.Do(req)
	if err != nil {
		debug.Printf("request failed for url %q: %v", req.URL.String(), err)
		return err
	}
	defer res.Body.Close()
	debug.Printf("%s %s: %s", res.Request.Method, res.Request.URL.Path, res.Status)
	switch res.StatusCode {
	case http.StatusOK:
	case http.StatusCreated:
		//
	default:
		return fmt.Errorf("unexpected return status: %d", res.StatusCode)
	}
	var report claircore.IndexReport
	dec := codec.GetDecoder(res.Body)
	defer codec.PutDecoder(dec)
	if err := dec.Decode(&report); err != nil {
		debug.Printf("unable to decode json payload: %v", err)
		return err
	}
	if !report.Success && report.Err != "" {
		return errors.New("indexer error: " + report.Err)
	}
	if v := res.Header.Get("etag"); v != "" {
		ls := linkheader.ParseMultiple(res.Header[http.CanonicalHeaderKey("link")]).
			FilterByRel("https://projectquay.io/clair/v1/index_report")
		if len(ls) > 0 {
			u, err := url.Parse(ls[0].URL)
			if err != nil {
				return err
			}
			c.setValidator(u.Path, v)
		}
	}
	return nil
}

func (c *Client) VulnerabilityReport(ctx context.Context, id claircore.Digest) (*claircore.VulnerabilityReport, error) {
	var (
		req *http.Request
		res *http.Response
	)
	u, err := c.host.Parse(path.Join(c.host.RequestURI(), httptransport.VulnerabilityReportPath, id.String()))
	if err != nil {
		debug.Printf("unable to construct vulnerability_report url: %v", err)
		return nil, err
	}
	req = c.request(ctx, u, http.MethodGet)
	res, err = c.client.Do(req)
	if err != nil {
		debug.Printf("request failed for url %q: %v", req.URL.String(), err)
		return nil, err
	}
	defer res.Body.Close()
	debug.Printf("%s %s: %s", res.Request.Method, res.Request.URL.Path, res.Status)
	switch res.StatusCode {
	case http.StatusOK:
	case http.StatusNotModified:
		// ???
		return nil, errors.New("not modified")
	default:
		return nil, fmt.Errorf("unexpected return status: %d", res.StatusCode)
	}
	var report claircore.VulnerabilityReport
	dec := codec.GetDecoder(res.Body)
	defer codec.PutDecoder(dec)
	if err := dec.Decode(&report); err != nil {
		debug.Printf("unable to decode json payload: %v", err)
		return nil, err
	}

	return &report, nil
}

func (c *Client) request(ctx context.Context, u *url.URL, m string) *http.Request {
	req := &http.Request{
		Method:     m,
		URL:        u,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
		Body:       nil,
		Host:       u.Host,
	}
	req = req.WithContext(ctx)
	req.Header.Set("user-agent", userAgent)
	if v := c.getValidator(u.EscapedPath()); v != "" {
		req.Header.Set("if-none-match", v)
	}
	return req
}
