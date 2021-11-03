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

// TestUpdateOperationHandler is a parallel harness for testing a UpdateOperation handler.
func TestUpdateOperationHandler(t *testing.T) {
	t.Run("Methods", testUpdateOperationHandlerMethods)
	t.Run("Get", testUpdateOperationHandlerGet)
	t.Run("Delete", testUpdateOperationHandlerGet)
	t.Run("Errors", testUpdateOperationHandlerErrors)
}

// testUpdateOperationHandlerErrors confirms the handler performs the correct
// actions when a matcher.Differ is failing.
func testUpdateOperationHandlerErrors(t *testing.T) {
	t.Parallel()

	id := uuid.New().String()
	var ErrExpected error = fmt.Errorf("expected error")
	h := UpdateOperationHandler(&matcher.Mock{
		DeleteUpdateOperations_: func(context.Context, ...uuid.UUID) (int64, error) { return 0, ErrExpected },
		// this will not immediately fail the handler
		LatestUpdateOperation_: func(context.Context, driver.UpdateKind) (uuid.UUID, error) {
			return uuid.Nil, ErrExpected
		},
		LatestUpdateOperations_: func(context.Context, driver.UpdateKind) (map[string][]driver.UpdateOperation, error) {
			return nil, ErrExpected
		},
		UpdateOperations_: func(context.Context, driver.UpdateKind, ...string) (map[string][]driver.UpdateOperation, error) {
			return nil, ErrExpected
		},
	})
	srv := httptest.NewServer(h)
	defer srv.Close()
	c := srv.Client()

	// perform get with failing differ
	req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("failed to make request: %v", err)
	}
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("got: %v, want: %v", resp.StatusCode, http.StatusInternalServerError)
	}

	// perform delete with failing differ
	u := srv.URL + "/" + id
	req, err = http.NewRequest(http.MethodDelete, u, nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	resp, err = c.Do(req)
	if err != nil {
		t.Fatalf("failed to make request: %v", err)
	}
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("got: %v, want: %v", resp.StatusCode, http.StatusInternalServerError)
	}
}

// testUpdateOperationHandlerMethods confirms the handler only responds
// to the desired methods.
func testUpdateOperationHandlerMethods(t *testing.T) {
	t.Parallel()
	h := UpdateOperationHandler(&matcher.Mock{})
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

// testUpdateOperationDelete confirms the handler performs the correct
// actions on Delete.
func testUpdateOperationDelete(t *testing.T) {
	t.Parallel()

	h := UpdateOperationHandler(&matcher.Mock{
		DeleteUpdateOperations_: func(context.Context, ...uuid.UUID) (int64, error) { return 0, nil },
	})
	srv := httptest.NewServer(h)
	defer srv.Close()
	c := srv.Client()

	id := uuid.New().String()
	u := srv.URL + "/" + id
	req, err := http.NewRequest(http.MethodDelete, u, nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("failed to do request: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got: %v, want: %v", resp.StatusCode, http.StatusOK)
	}
}

// testUpdateOperationHandlerGet confirms the handler performs the correct
// actions on GET.
func testUpdateOperationHandlerGet(t *testing.T) {
	t.Parallel()

	id := uuid.New()
	idStr := "\"" + id.String() + "\""
	var called bool
	var latestCalled bool
	h := UpdateOperationHandler(&matcher.Mock{
		LatestUpdateOperation_: func(context.Context, driver.UpdateKind) (uuid.UUID, error) {
			return id, nil
		},
		LatestUpdateOperations_: func(context.Context, driver.UpdateKind) (map[string][]driver.UpdateOperation, error) {
			latestCalled = true
			return nil, nil
		},
		UpdateOperations_: func(context.Context, driver.UpdateKind, ...string) (map[string][]driver.UpdateOperation, error) {
			called = true
			return nil, nil
		},
	})
	srv := httptest.NewServer(h)
	defer srv.Close()
	c := srv.Client()

	// get without latest param
	req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("failed to make request: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got: %v, want: %v", resp.StatusCode, http.StatusOK)
	}
	if !called {
		t.Fatalf("got: %v, want: %v", called, true)
	}
	etag := resp.Header.Get("etag")
	if etag != idStr {
		t.Fatalf("got: %v, want: %v", etag, id.String())
	}

	// get with latest param
	u, _ := url.Parse(srv.URL)
	q := u.Query()
	q.Add("latest", "true")
	u.RawQuery = q.Encode()
	req = &http.Request{
		URL:    u,
		Method: http.MethodGet,
	}
	resp, err = c.Do(req)
	if err != nil {
		t.Fatalf("failed to make request: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got: %v, want: %v", resp.StatusCode, http.StatusOK)
	}
	if !latestCalled {
		t.Fatalf("got: %v, want: %v", latestCalled, true)
	}
	etag = resp.Header.Get("etag")
	if etag != idStr {
		t.Fatalf("got: %v, want: %v", etag, id.String())
	}
}
