package httptransport

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/quay/claircore"

	"github.com/quay/clair/v4/indexer"
)

// TestAffectedManifestHandler is a parallel harness for testing an AffectedManifest handler.
func TestAffectedManifestHandler(t *testing.T) {
	t.Run("IndexerOK", testAffectedManifestHandlerIndexerOK)
	t.Run("IndexerErr", testAffectedManifestHandlerIndexerErr)
	t.Run("Methods", testAffectedManifestHandlerMethods)
}

func testAffectedManifestHandlerIndexerOK(t *testing.T) {
	t.Parallel()
	h := AffectedManifestHandler(&indexer.Mock{
		AffectedManifests_: func(context.Context, []claircore.Vulnerability) (*claircore.AffectedManifests, error) {
			return &claircore.AffectedManifests{}, nil
		},
	})

	srv := httptest.NewServer(h)
	defer srv.Close()
	c := srv.Client()

	buf := &bytes.Buffer{}
	err := json.NewEncoder(buf).Encode(struct {
		V []claircore.Vulnerability `json:"vulnerabilities"`
	}{})
	if err != nil {
		t.Fatalf("failed to marshall vulnerabilities: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, srv.URL, buf)
	if err != nil {
		t.Fatalf("failed to create test request: %v", err)
	}

	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("failed to do request: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got: %v, want: %v", resp.StatusCode, http.StatusOK)
	}
}

func testAffectedManifestHandlerIndexerErr(t *testing.T) {
	t.Parallel()
	h := AffectedManifestHandler(&indexer.Mock{
		AffectedManifests_: func(context.Context, []claircore.Vulnerability) (*claircore.AffectedManifests, error) {
			return nil, fmt.Errorf("failed")
		},
	})

	srv := httptest.NewServer(h)
	defer srv.Close()
	c := srv.Client()

	buf := &bytes.Buffer{}
	err := json.NewEncoder(buf).Encode(struct {
		V []claircore.Vulnerability `json:"vulnerabilities"`
	}{})
	if err != nil {
		t.Fatalf("failed to marshall vulnerabilities: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, srv.URL, buf)
	if err != nil {
		t.Fatalf("failed to create test request: %v", err)
	}

	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("failed to do request: %v", err)
	}

	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("got: %v, want: %v", resp.StatusCode, http.StatusInternalServerError)
	}
}

func testAffectedManifestHandlerMethods(t *testing.T) {
	t.Parallel()
	h := AffectedManifestHandler(&indexer.Mock{
		AffectedManifests_: func(context.Context, []claircore.Vulnerability) (*claircore.AffectedManifests, error) {
			return &claircore.AffectedManifests{}, nil
		},
	})
	srv := httptest.NewServer(h)
	defer srv.Close()
	c := srv.Client()

	for _, m := range []string{
		http.MethodConnect,
		http.MethodHead,
		http.MethodOptions,
		http.MethodPatch,
		http.MethodGet,
		http.MethodDelete,
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
