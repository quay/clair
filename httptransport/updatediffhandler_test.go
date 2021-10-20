package httptransport

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/uuid"
	"github.com/quay/claircore/libvuln/driver"

	"github.com/quay/clair/v4/matcher"
)

// TestUpdateDiffHandler is a parallel harness for testing a UpdateDiff handler.
func TestUpdateDiffHandler(t *testing.T) {
	t.Run("Matcher", testUpdateDiffMatcher)
	t.Run("Params", testUpdateDiffHandlerParams)
	t.Run("Methods", testUpdateDiffHandlerMethods)
}

// TestUpdateDiffMatcher confirms the UpdateDiff handler provides
// the correct status codes when a matcher returns an error or success
func testUpdateDiffMatcher(t *testing.T) {
	t.Parallel()
	hOK := UpdateDiffHandler(&matcher.Mock{
		UpdateDiff_: func(context.Context, uuid.UUID, uuid.UUID) (*driver.UpdateDiff, error) { return nil, nil },
	})
	hErr := UpdateDiffHandler(&matcher.Mock{
		UpdateDiff_: func(context.Context, uuid.UUID, uuid.UUID) (*driver.UpdateDiff, error) {
			return nil, fmt.Errorf("expected error")
		},
	})
	srvOK := httptest.NewServer(hOK)
	srvErr := httptest.NewServer(hErr)
	defer srvOK.Close()
	defer srvErr.Close()
	cOK := srvOK.Client()
	cErr := srvErr.Client()

	// test matcher returns nil error
	url, err := url.Parse(srvOK.URL)
	if err != nil {
		t.Fatalf("failed to parse test server URL into *net/URL")
	}
	q := url.Query()
	q.Set("cur", "892737b2-a616-4113-a7a9-137139c8f91e")
	url.RawQuery = q.Encode()

	req := &http.Request{
		URL:    url,
		Method: http.MethodGet,
	}
	resp, err := cOK.Do(req)
	if err != nil {
		t.Fatalf("failed to do request: %v", err)
	}
	got, want := resp.StatusCode, http.StatusOK
	if got != want {
		t.Fatalf("got: %v, want: %v", got, want)
	}

	// test matcher returns error
	url, err = url.Parse(srvErr.URL)
	if err != nil {
		t.Fatalf("failed to parse test server URL into *net/URL")
	}
	q = url.Query()
	q.Set("cur", "892737b2-a616-4113-a7a9-137139c8f91e")
	url.RawQuery = q.Encode()

	req = &http.Request{
		URL:    url,
		Method: http.MethodGet,
	}
	resp, err = cErr.Do(req)
	if err != nil {
		t.Fatalf("failed to do request: %v", err)
	}
	got, want = resp.StatusCode, http.StatusInternalServerError
	if got != want {
		t.Fatalf("got: %v, want: %v", got, want)
	}
}

// TestUpdateDiffHandlerParams confirms the UpdateDiff handler
// returns correct status codes given a set or url parameters
func testUpdateDiffHandlerParams(t *testing.T) {
	t.Parallel()
	table := []struct {
		name       string
		cur        string
		prev       string
		statusCode int
	}{
		{
			name:       "no params",
			cur:        "",
			prev:       "",
			statusCode: http.StatusBadRequest,
		},
		{
			name:       "missing prev",
			cur:        "892737b2-a616-4113-a7a9-137139c8f91e",
			prev:       "",
			statusCode: http.StatusOK,
		},
		{
			name:       "missing cur",
			cur:        "",
			prev:       "892737b2-a616-4113-a7a9-137139c8f91e",
			statusCode: http.StatusBadRequest,
		},
		{
			name:       "all params",
			cur:        "6ea97b35-d886-4845-8ba2-5a4b0a074bfe",
			prev:       "892737b2-a616-4113-a7a9-137139c8f91e",
			statusCode: http.StatusOK,
		},
	}

	h := UpdateDiffHandler(&matcher.Mock{
		UpdateDiff_: func(context.Context, uuid.UUID, uuid.UUID) (*driver.UpdateDiff, error) { return nil, nil },
	})
	srv := httptest.NewServer(h)
	defer srv.Close()
	c := srv.Client()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("failed to parse test server URL into *net/URL")
	}

	for _, test := range table {
		t.Run(test.name, func(t *testing.T) {
			q := u.Query()
			q.Set("cur", test.cur)
			q.Set("prev", test.cur)
			u.RawQuery = q.Encode()

			req := &http.Request{
				URL:    u,
				Method: http.MethodGet,
			}
			resp, err := c.Do(req)
			if err != nil {
				t.Fatalf("failed to do request: %v", err)
			}
			got, want := resp.StatusCode, test.statusCode
			if got != want {
				t.Fatalf("got: %v, want: %v", got, want)
			}
		})
	}
}

// TestUpdateDiffHandlerMethods confirms the UpdateDiffHandler responds correctly
// to unaccepted HTTP methods.
func testUpdateDiffHandlerMethods(t *testing.T) {
	t.Parallel()
	h := UpdateDiffHandler(&matcher.Mock{
		UpdateDiff_: func(context.Context, uuid.UUID, uuid.UUID) (*driver.UpdateDiff, error) { return nil, nil },
	})
	srv := httptest.NewServer(h)
	defer srv.Close()
	c := srv.Client()

	for _, m := range []string{
		http.MethodConnect,
		http.MethodHead,
		http.MethodOptions,
		http.MethodPatch,
		http.MethodPost,
		http.MethodPut,
		http.MethodTrace,
	} {
		req, err := http.NewRequest(m, srv.URL, nil)
		if err != nil {
			t.Fatalf("failed to create request: %v", err)
		}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatalf("failed to make request: %v", err)
		}
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("method: %v got: %v want: %v", m, resp.Status, http.StatusMethodNotAllowed)
		}
	}
}
