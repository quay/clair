package client

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/google/uuid"
	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"

	clairerror "github.com/quay/clair/v4/clair-error"
	"github.com/quay/clair/v4/httptransport"
	"github.com/quay/clair/v4/internal/codec"
	"github.com/quay/clair/v4/internal/httputil"
	"github.com/quay/clair/v4/matcher"
)

var _ matcher.Service = (*HTTP)(nil)

func (c *HTTP) Scan(ctx context.Context, ir *claircore.IndexReport) (*claircore.VulnerabilityReport, error) {
	u, err := c.addr.Parse(httptransport.VulnerabilityReportPath)
	if err != nil {
		return nil, err
	}
	req, err := httputil.NewRequestWithContext(ctx, http.MethodPost, u.String(), codec.JSONReader(ir))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	if err := c.sign(ctx, req); err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("content-type", `application/json`)
	resp, err := c.c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, &clairerror.ErrRequestFail{
			Code:   resp.StatusCode,
			Status: resp.Status,
		}
	}

	var vr claircore.VulnerabilityReport
	switch ct := req.Header.Get("content-type"); ct {
	case "", `application/json`:
		dec := codec.GetDecoder(resp.Body)
		defer codec.PutDecoder(dec)
		if err := dec.Decode(&vr); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unrecognized content-type %q", ct)
	}
	return &vr, nil
}

// DeleteUpdateOperations attempts to delete the referenced update operations.
func (c *HTTP) DeleteUpdateOperations(ctx context.Context, ref ...uuid.UUID) (int64, error) {
	u, err := c.addr.Parse(httptransport.UpdateOperationDeleteAPIPath)
	if err != nil {
		return 0, err
	}

	// Spawn a few requests that will write their result into "errs".
	//
	// These'll most likely be multiplexed and to the same host, so pick a nice
	// lowish number like 4.
	//
	// Don't use an errgroup because we want to actually issue all the DELETEs,
	// not stop all requests on the first error.
	var wg sync.WaitGroup
	item := make(chan int)
	errs := make([]error, len(ref))
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range item {
				u, err := u.Parse(ref[i].String())
				if err != nil {
					errs[i] = err
					return
				}
				req, err := httputil.NewRequestWithContext(ctx, http.MethodDelete, u.String(), nil)
				if err != nil {
					errs[i] = err
					return
				}
				if err := c.sign(ctx, req); err != nil {
					errs[i] = fmt.Errorf("failed to create request: %v", err)
					return
				}
				res, err := c.c.Do(req)
				if err != nil {
					errs[i] = err
					return
				}
				defer res.Body.Close()
				if got, want := res.StatusCode, http.StatusOK; got != want {
					errs[i] = fmt.Errorf("%v: unexpected status: %s", u.Path, res.Status)
				}
			}
		}()
	}
	for i, lim := 0, len(ref); i < lim; i++ {
		item <- i
	}
	close(item)
	wg.Wait()

	var b strings.Builder
	var errd bool
	deleted := int64(len(ref))
	for _, err := range errs {
		if err != nil {
			deleted--
			if errd {
				b.WriteByte('\n')
			}
			b.WriteString(err.Error())
			errd = true
		}
	}

	if errd {
		return deleted, errors.New("deletion errors: " + b.String())
	}
	return deleted, nil
}

// LatestUpdateOperation shouldn't be used by client code and is implemented
// only to satisfy the matcher.Differ interface.
func (c *HTTP) LatestUpdateOperation(_ context.Context, _ driver.UpdateKind) (uuid.UUID, error) {
	return uuid.Nil, nil
}

// UpdateOperations returns all the known UpdateOperations per updater.
func (c *HTTP) UpdateOperations(ctx context.Context, k driver.UpdateKind, updaters ...string) (map[string][]driver.UpdateOperation, error) {
	u, err := c.addr.Parse(httptransport.UpdateOperationAPIPath)
	if err != nil {
		return nil, err
	}
	v := url.Values{}
	v.Add("kind", string(k))
	u.RawQuery = v.Encode()
	req, err := httputil.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	if err := c.sign(ctx, req); err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	return c.updateOperations(ctx, req, c.uoCache)
}

// LatestUpdateOperations returns the most recent UpdateOperation per updater.
func (c *HTTP) LatestUpdateOperations(ctx context.Context, k driver.UpdateKind) (map[string][]driver.UpdateOperation, error) {
	u, err := c.addr.Parse(httptransport.UpdateOperationAPIPath)
	if err != nil {
		return nil, err
	}
	v := url.Values{}
	v.Add("latest", "true")
	v.Add("kind", string(k))
	u.RawQuery = v.Encode()

	req, err := httputil.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}

	// check the cache validator and pass our ouCache to
	// updateOperations
	c.uoLatestCache.RLock()
	if c.uoLatestCache.validator != "" {
		req.Header.Set("if-none-match", c.uoLatestCache.validator)
	}
	c.uoLatestCache.RUnlock()
	return c.updateOperations(ctx, req, c.uoLatestCache)
}

// updateOperations is a private method implementing the common bits for retrieving UpdateOperations
//
// an ouCache is passed in by the caller to cache any responses providing an etag.
// if a subsequent response provides a StatusNotModified status, the map of UpdateOprations is served from cache.
func (c *HTTP) updateOperations(ctx context.Context, req *http.Request, cache *uoCache) (map[string][]driver.UpdateOperation, error) {
	if err := c.sign(ctx, req); err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	res, err := c.c.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	switch res.StatusCode {
	case http.StatusOK:
		m := make(map[string][]driver.UpdateOperation)
		dec := codec.GetDecoder(res.Body)
		defer codec.PutDecoder(dec)
		if err := dec.Decode(&m); err != nil {
			return nil, err
		}
		// check for etag, if exists store the value and add returned map
		// to cache
		if v := res.Header.Get("etag"); v != "" && !strings.HasPrefix(v, "W/") {
			cache.Set(m, v)
		}
		return cache.Copy(), nil
	case http.StatusNotModified:
		return cache.Copy(), nil
	default:
	}
	return nil, fmt.Errorf("%v: unexpected status: %s", req.URL.Path, res.Status)
}

// UpdateDiff reports the diff of two update operations, identified by the
// provided refs.
//
// "Prev" may be passed uuid.Nil if the client's last known state has been
// forgotten by the server.
func (c *HTTP) UpdateDiff(ctx context.Context, prev, cur uuid.UUID) (*driver.UpdateDiff, error) {
	u, err := c.addr.Parse(httptransport.UpdateDiffAPIPath)
	if err != nil {
		return nil, err
	}
	req, err := httputil.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	v := req.URL.Query()
	if prev != uuid.Nil {
		v.Set("prev", prev.String())
	}
	v.Set("cur", cur.String())
	req.URL.RawQuery = v.Encode()
	if err := c.sign(ctx, req); err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	res, err := c.c.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%v: unexpected status: %s", u.Path, res.Status)
	}
	d := driver.UpdateDiff{}
	dec := codec.GetDecoder(res.Body)
	defer codec.PutDecoder(dec)
	if err := dec.Decode(&d); err != nil {
		return nil, err
	}
	return &d, nil
}

// Initialized is present to fulfill the interface, but isn't exposed as part of
// the HTTP API. This method is stubbed out.
func (c *HTTP) Initialized(_ context.Context) (bool, error) {
	return true, nil
}
