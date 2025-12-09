package httptransport

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/quay/zlog"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/trace/noop"
)

func TestDiscovery(t *testing.T) {
	t.Run("Endpoint", func(t *testing.T) {
		ctx := zlog.Test(context.Background(), t)
		h := DiscoveryHandler(ctx, OpenAPIV1Path, otelhttp.WithTracerProvider(noop.NewTracerProvider()))

		r := httptest.NewRecorder()
		req := httptest.NewRequest("GET", OpenAPIV1Path, nil).WithContext(ctx)
		req.Header.Set("Accept", "application/yaml; q=0.4, application/json; q=0.4, application/vnd.oai.openapi+json; q=0.6, application/openapi+json")
		h.ServeHTTP(r, req)

		resp := r.Result()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("got status code: %v want status code: %v", resp.StatusCode, http.StatusOK)
		}
		if got, want := resp.Header.Get("content-type"), "application/openapi+json"; got != want {
			t.Errorf("got: %q, want: %q", got, want)
		}

		buf, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("failed to ready response body: %v", err)
		}

		m := make(map[string]any)
		err = json.Unmarshal(buf, &m)
		if err != nil {
			t.Fatalf("failed to json parse returned bytes: %v", err)
		}

		if _, ok := m["openapi"]; !ok {
			t.Fatalf("returned json did not container openapi key at the root")
		}
		t.Logf("openapi verion: %v", m["openapi"])
	})

	t.Run("Failure", func(t *testing.T) {
		ctx := zlog.Test(context.Background(), t)
		h := DiscoveryHandler(ctx, OpenAPIV1Path, otelhttp.WithTracerProvider(noop.NewTracerProvider()))

		r := httptest.NewRecorder()
		// Needed because handlers exit the goroutine.
		done := make(chan struct{})
		go func() {
			defer close(done)
			req := httptest.NewRequest("GET", OpenAPIV1Path, nil).WithContext(ctx)
			req.Header.Set("Accept", "application/xml")
			h.ServeHTTP(r, req)
		}()
		<-done

		resp := r.Result()
		t.Log(resp.Status)
		if got, want := resp.StatusCode, http.StatusUnsupportedMediaType; got != want {
			t.Errorf("got status code: %v want status code: %v", got, want)
		}
	})
}
