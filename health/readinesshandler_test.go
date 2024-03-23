package health_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/quay/clair/v4/health"
	"github.com/quay/clair/v4/internal/httputil"
)

func TestReadinessHandler(t *testing.T) {
	ctx := context.Background()

	// Create a test server and defer its closure
	server := httptest.NewServer(health.ReadinessHandler())
	defer server.Close()

	client := server.Client()

	makeRequest := func() (*http.Response, error) {
		req, err := httputil.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %v", err)
		}
		return client.Do(req)
	}

	checkStatusCode := func(expected, actual int) {
		if expected != actual {
			t.Errorf("expected status code %d, got %d", expected, actual)
		}
	}

	// Default handler state should return StatusServiceUnavailable
	resp, err := makeRequest()
	if err != nil {
		t.Errorf("failed to do request: %v", err)
	}
	checkStatusCode(http.StatusServiceUnavailable, resp.StatusCode)

	// Signal to handler that the process is ready. Should return StatusOK
	health.Ready()
	resp, err = makeRequest()
	if err != nil {
		t.Errorf("failed to do request: %v", err)
	}
	checkStatusCode(http.StatusOK, resp.StatusCode)

	// Signal to handler that the process is unready. Should return StatusServiceUnavailable
	health.Unready()
	resp, err = makeRequest()
	if err != nil {
		t.Errorf("failed to do request: %v", err)
	}
	checkStatusCode(http.StatusServiceUnavailable, resp.StatusCode)
}
