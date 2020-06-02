package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path"
	"strings"
	"sync"

	"github.com/google/uuid"
	"github.com/quay/claircore/libvuln/driver"

	"github.com/quay/clair/v4/httptransport"
	"github.com/quay/clair/v4/matcher"
)

var _ matcher.Differ = (*HTTP)(nil)

// DeleteUpdateOperations attempts to delete the referenced update operations.
func (c *HTTP) DeleteUpdateOperations(ctx context.Context, ref ...uuid.UUID) error {
	u, err := c.addr.Parse(httptransport.UpdatesAPIPath)
	if err != nil {
		return err
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
	for _, err := range errs {
		if err != nil {
			if errd {
				b.WriteByte('\n')
			}
			b.WriteString(err.Error())
			errd = true
		}
	}

	if errd {
		return errors.New("deletion errors: " + b.String())
	}
	return nil
}

// LatestUpdateOperation shouldn't be used by client code and is implemented
// only to satisfy the matcher.Differ interface.
func (c *HTTP) LatestUpdateOperation(_ context.Context) (uuid.UUID, error) {
	return uuid.Nil, nil
}

// ErrUnchanged is returned from LatestUpdateOperations if there have been no
// new update operations since the last call.
var ErrUnchanged = errors.New("response unchanged from last call")

// LatestUpdateOperations returns a map of updater name to ref of its latest
// update.
func (c *HTTP) LatestUpdateOperations(ctx context.Context) (map[string]uuid.UUID, error) {
	u, err := c.addr.Parse(httptransport.UpdatesAPIPath)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	if v := c.diffValidator.Load().(string); v != "" {
		req.Header.Set("if-none-match", v)
	}
	res, err := c.c.Do(req)
	if res != nil {
		defer res.Body.Close()
	}
	if err != nil {
		return nil, err
	}
	switch res.StatusCode {
	case http.StatusOK:
		if v := res.Header.Get("etag"); v != "" && !strings.HasPrefix(v, "W/") {
			c.diffValidator.Store(v)
		}
	case http.StatusNotModified:
		return nil, ErrUnchanged
	default:
		return nil, fmt.Errorf("%v: unexpected status: %s", u.Path, res.Status)
	}
	m := make(map[string]uuid.UUID)
	if err := json.NewDecoder(res.Body).Decode(&m); err != nil {
		return nil, err
	}
	return m, nil
}

// UpdateDiff reports the diff of two update operations, identified by the
// provided refs.
//
// "Prev" may be passed uuid.Nil if the client's last known state has been
// forgotten by the server.
func (c *HTTP) UpdateDiff(ctx context.Context, prev, cur uuid.UUID) (*driver.UpdateDiff, error) {
	u, err := c.addr.Parse(path.Join(httptransport.UpdatesAPIPath, "diff"))
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
