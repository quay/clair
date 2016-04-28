package clair

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func newServer(httpStatus int) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(httpStatus)
	}))
}

func TestIsHealthy(t *testing.T) {
	server := newServer(http.StatusOK)
	defer server.Close()
	uri = server.URL
	if h := IsHealthy(); !h {
		t.Errorf("IsHealthy() => %v, want %v", h, true)
	}
}

func TestIsNotHealthy(t *testing.T) {
	server := newServer(http.StatusInternalServerError)
	defer server.Close()
	uri = server.URL
	if h := IsHealthy(); h {
		t.Errorf("IsHealthy() => %v, want %v", h, true)
	}
}
