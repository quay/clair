package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"sync"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/quay/claircore"
	"github.com/quay/zlog"
	"github.com/tomnomnom/linkheader"

	"github.com/quay/clair/v4/cmd"
	"github.com/quay/clair/v4/httptransport"
	"github.com/quay/clair/v4/internal/codec"
	"github.com/quay/clair/v4/internal/httputil"
)

var (
	rtMu  sync.Mutex
	rtMap = map[string]http.RoundTripper{}
)

func rt(ctx context.Context, ref string) (http.RoundTripper, error) {
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
	rt := http.DefaultTransport
	rt = transport.NewUserAgent(rt, `clairctl/`+cmd.Version)
	rt = transport.NewRetry(rt)
	rt, err = transport.NewWithContext(ctx, repo.Registry, auth, rt, []string{repo.Scope(transport.PullScope)})
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
	signer *httputil.Signer

	mu sync.RWMutex
	// TODO Back this on disk to minimize resubmissions.
	validator map[string]string
}

func NewClient(c *http.Client, root string, s *httputil.Signer) (*Client, error) {
	if c == nil {
		return nil, errors.New("programmer error: no http.Client provided")
	}
	host, err := url.Parse(root)
	if err != nil {
		return nil, err
	}
	return &Client{
		host:      host,
		client:    c,
		signer:    s,
		validator: make(map[string]string),
	}, nil
}

func (c *Client) getValidator(_ context.Context, path string) string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.validator[path]
}

func (c *Client) setValidator(ctx context.Context, path, v string) {
	zlog.Debug(ctx).
		Str("path", path).
		Str("validator", v).
		Msg("setting validator")
	c.mu.Lock()
	defer c.mu.Unlock()
	c.validator[path] = v
}

var (
	errNeedManifest  = errors.New("manifest needed but not supplied")
	errNovelManifest = errors.New("manifest unknown to the system")
)

func (c *Client) IndexReport(ctx context.Context, id claircore.Digest, m *claircore.Manifest) error {
	var (
		req *http.Request
		res *http.Response
	)
	fp, err := c.host.Parse(path.Join(c.host.RequestURI(), httptransport.IndexReportAPIPath, id.String()))
	if err != nil {
		zlog.Debug(ctx).
			Err(err).
			Msg("unable to construct index_report url")
		return err
	}
	req, err = c.request(ctx, fp, http.MethodGet)
	if err != nil {
		return err
	}
	res, err = c.client.Do(req)
	if err != nil {
		zlog.Debug(ctx).
			Err(err).
			Stringer("url", req.URL).
			Msg("request failed")
		return err
	}
	defer res.Body.Close()
	ev := zlog.Debug(ctx).
		Str("method", res.Request.Method).
		Str("path", res.Request.URL.Path).
		Str("status", res.Status)
	if ev.Enabled() && res.ContentLength > 0 && res.ContentLength <= 256 {
		var buf bytes.Buffer
		buf.ReadFrom(io.LimitReader(res.Body, 256))
		ev.Stringer("body", &buf)
	}
	ev.Send()
	switch res.StatusCode {
	case http.StatusNotFound, http.StatusOK:
	case http.StatusNotModified:
		return nil
	default:
		return fmt.Errorf("unexpected return status: %d", res.StatusCode)
	}

	if m == nil {
		ev := zlog.Debug(ctx).
			Stringer("manifest", id)
		if res.StatusCode == http.StatusNotFound {
			ev.Msg("don't have needed manifest")
			return errNovelManifest
		}
		ev.Msg("manifest may be out-of-date")
		return errNeedManifest
	}
	ru, err := c.host.Parse(path.Join(c.host.RequestURI(), httptransport.IndexAPIPath))
	if err != nil {
		zlog.Debug(ctx).
			Err(err).
			Msg("unable to construct index_report url")
		return err
	}

	req, err = c.request(ctx, ru, http.MethodPost)
	if err != nil {
		return err
	}
	req.Body = codec.JSONReader(m)
	res, err = c.client.Do(req)
	if err != nil {
		zlog.Debug(ctx).
			Err(err).
			Stringer("url", req.URL).
			Msg("request failed")
		return err
	}
	defer res.Body.Close()
	zlog.Debug(ctx).
		Str("method", res.Request.Method).
		Str("path", res.Request.URL.Path).
		Str("status", res.Status).
		Send()
	switch res.StatusCode {
	case http.StatusOK:
	case http.StatusCreated:
		//
	default:
		return fmt.Errorf("unexpected return status: %d", res.StatusCode)
	}
	var rd io.Reader
	switch {
	case res.ContentLength > 0 && res.ContentLength < 32+9:
		// Less than the size of the digest representation, something's up.
		var buf bytes.Buffer
		// Ignore error, because what would we do with it here?
		ct, _ := buf.ReadFrom(res.Body)
		zlog.Info(ctx).
			Int64("size", ct).
			Stringer("response", &buf).
			Msg("body seems short")
		rd = &buf
	case res.ContentLength < 0: // Streaming
		fallthrough
	default:
		rd = res.Body
	}
	var report claircore.IndexReport
	dec := codec.GetDecoder(rd)
	defer codec.PutDecoder(dec)
	if err := dec.Decode(&report); err != nil {
		zlog.Debug(ctx).
			Err(err).
			Msg("unable to decode json payload")
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
			c.setValidator(ctx, u.Path, v)
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
		zlog.Debug(ctx).
			Err(err).
			Msg("unable to construct vulnerability_report url")
		return nil, err
	}
	req, err = c.request(ctx, u, http.MethodGet)
	if err != nil {
		return nil, err
	}
	res, err = c.client.Do(req)
	if err != nil {
		zlog.Debug(ctx).
			Err(err).
			Stringer("url", req.URL).
			Msg("request failed")
		return nil, err
	}
	defer res.Body.Close()
	zlog.Debug(ctx).
		Str("method", res.Request.Method).
		Str("path", res.Request.URL.Path).
		Str("status", res.Status).
		Send()
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
		zlog.Debug(ctx).
			Err(err).
			Msg("unable to decode json payload")
		return nil, err
	}

	return &report, nil
}

func (c *Client) DeleteIndexReports(ctx context.Context, ds []claircore.Digest) error {
	var (
		req *http.Request
		res *http.Response
	)
	u, err := c.host.Parse(path.Join(c.host.RequestURI(), httptransport.IndexAPIPath))
	if err != nil {
		return err
	}
	req, err = c.request(ctx, u, http.MethodDelete)
	if err != nil {
		return err
	}

	req.Body = codec.JSONReader(ds)
	res, err = c.client.Do(req)
	if err != nil {
		zlog.Debug(ctx).
			Err(err).
			Stringer("url", req.URL).
			Msg("request failed")
		return err
	}
	defer res.Body.Close()
	zlog.Debug(ctx).
		Str("method", res.Request.Method).
		Str("path", res.Request.URL.Path).
		Str("status", res.Status).
		Send()
	switch res.StatusCode {
	case http.StatusOK:
	default:
		return fmt.Errorf("unexpected return status: %d", res.StatusCode)
	}
	return nil
}

func (c *Client) request(ctx context.Context, u *url.URL, m string) (*http.Request, error) {
	req, err := httputil.NewRequestWithContext(ctx, m, u.String(), nil)
	if err != nil {
		return nil, err
	}
	if v := c.getValidator(ctx, u.EscapedPath()); v != "" {
		req.Header.Set("if-none-match", v)
	}
	if c.signer != nil {
		if err := c.signer.Sign(ctx, req); err != nil {
			return nil, err
		}
	}
	return req, nil
}
