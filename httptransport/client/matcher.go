package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/google/uuid"
	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"

	"github.com/quay/clair/v4/httptransport"
	"github.com/quay/clair/v4/matcher"
)

var _ matcher.Service = (*HTTP)(nil)

func (c *HTTP) Scan(ctx context.Context, ir *claircore.IndexReport) (*claircore.VulnerabilityReport, error) {
	u, err := c.addr.Parse(httptransport.VulnerabilityReportPath)
	if err != nil {
		return nil, err
	}

	b, err := json.Marshal(&ir)
	if err != nil {
		return nil, err
	}
	buf := bytes.NewBuffer(b)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), buf)
	if err != nil {
		return nil, err
	}

	resp, err := c.c.Do(req)
	if resp != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%v: unexpected status: %s", u.Path, resp.Status)
	}

	var vr claircore.VulnerabilityReport
	err = json.NewDecoder(resp.Body).Decode(&vr)
	if err != nil {
		return nil, err
	}
	return &vr, nil
}

// DeleteUpdateOperations attempts to delete the referenced update operations.
func (c *HTTP) DeleteUpdateOperations(ctx context.Context, ref ...uuid.UUID) (int64, error) {
	u, err := c.addr.Parse(httptransport.UpdateOperationAPIPath)
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
				req, err := http.NewRequestWithContext(ctx, http.MethodDelete, u.String(), nil)
				if err != nil {
					errs[i] = err
					return
				}
				res, err := c.c.Do(req)
				if res != nil {
					defer res.Body.Close()
				}
				if err != nil {
					errs[i] = err
					return
				}
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
	var deleted = int64(len(ref))
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
func (c *HTTP) LatestUpdateOperation(_ context.Context) (uuid.UUID, error) {
	return uuid.Nil, nil
}

// UpdateOperations returns all the known UpdateOperations per updater.
func (c *HTTP) UpdateOperations(ctx context.Context, updaters ...string) (map[string][]driver.UpdateOperation, error) {
	u, err := c.addr.Parse(httptransport.UpdateOperationAPIPath)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	return c.updateOperations(ctx, req, c.uoCache)
}

// LatestUpdateOperations returns the most recent UpdateOperation per updater.
func (c *HTTP) LatestUpdateOperations(ctx context.Context) (map[string][]driver.UpdateOperation, error) {
	u, err := c.addr.Parse(httptransport.UpdateOperationAPIPath)
	if err != nil {
		return nil, err
	}
	u.Query().Add("latest", "true")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
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
	res, err := c.c.Do(req)
	if res != nil {
		defer res.Body.Close()
	}
	if err != nil {
		return nil, err
	}
	switch res.StatusCode {
	case http.StatusOK:
		m := make(map[string][]driver.UpdateOperation)
		if err := json.NewDecoder(res.Body).Decode(&m); err != nil {
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	v := req.URL.Query()
	if prev != uuid.Nil {
		v.Set("prev", prev.String())
	}
	v.Set("cur", cur.String())
	req.URL.RawQuery = v.Encode()

	res, err := c.c.Do(req)
	if res != nil {
		defer res.Body.Close()
	}
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%v: unexpected status: %s", u.Path, res.Status)
	}
	d := driver.UpdateDiff{}
	if err := json.NewDecoder(res.Body).Decode(&d); err != nil {
		return nil, err
	}
	return &d, nil
}
