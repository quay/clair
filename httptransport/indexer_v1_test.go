package httptransport

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/quay/claircore"
	"github.com/quay/claircore/pkg/tarfs"
	"github.com/quay/zlog"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/trace"

	"github.com/quay/clair/v4/indexer"
	"github.com/quay/clair/v4/internal/httputil"
)

func TestIndexReportBadLayer(t *testing.T) {
	ctx := context.Background()
	ctx = zlog.Test(ctx, t)

	i := &indexer.Mock{
		State_: func(ctx context.Context) (string, error) {
			return `deadbeef`, nil
		},
		Index_: func(ctx context.Context, m *claircore.Manifest) (*claircore.IndexReport, error) {
			return nil, tarfs.ErrFormat
		},
	}
	v1, err := NewIndexerV1(ctx, "", i, otelhttp.WithTracerProvider(trace.NewNoopTracerProvider()))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(v1)
	srv.Config.BaseContext = func(_ net.Listener) context.Context { return ctx }
	srv.Start()
	defer srv.Close()
	t.Run("Report", func(t *testing.T) {
		ctx := zlog.Test(ctx, t)
		const path = `/index_report`
		t.Run("POST", func(t *testing.T) {
			const body = `{"hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000",` +
				`"layers":[{}]}`
			req, err := httputil.NewRequestWithContext(ctx, http.MethodPost, srv.URL+path, strings.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			res, err := srv.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			got, want := res.StatusCode, http.StatusBadRequest
			t.Logf("got: %d, want: %d", got, want)
			if got != want {
				t.Error()
			}
		})
	})
}

func TestIndexerV1(t *testing.T) {
	ctx := context.Background()
	ctx = zlog.Test(ctx, t)

	digest := claircore.MustParseDigest("sha256:0000000000000000000000000000000000000000000000000000000000000000")
	i := &indexer.Mock{
		State_: func(ctx context.Context) (string, error) {
			return `deadbeef`, nil
		},
		DeleteManifests_: func(_ context.Context, ds ...claircore.Digest) ([]claircore.Digest, error) {
			for _, d := range ds {
				if got, want := d.String(), digest.String(); got != want {
					return nil, fmt.Errorf("unexpected digest: %v", d)
				}
			}
			return ds, nil
		},
		Index_: func(ctx context.Context, m *claircore.Manifest) (*claircore.IndexReport, error) {
			return new(claircore.IndexReport), nil
		},
		IndexReport_: func(_ context.Context, d claircore.Digest) (*claircore.IndexReport, bool, error) {
			if got, want := d.String(), digest.String(); got != want {
				return nil, false, fmt.Errorf("unexpected digest: %v", d)
			}
			return new(claircore.IndexReport), true, nil
		},
		AffectedManifests_: func(_ context.Context, _ []claircore.Vulnerability) (*claircore.AffectedManifests, error) {
			return new(claircore.AffectedManifests), nil
		},
	}

	v1, err := NewIndexerV1(ctx, "", i, otelhttp.WithTracerProvider(trace.NewNoopTracerProvider()))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(v1)
	srv.Config.BaseContext = func(_ net.Listener) context.Context { return ctx }
	srv.Start()
	defer srv.Close()

	t.Run("State", func(t *testing.T) {
		ctx := zlog.Test(ctx, t)
		const path = `/index_state`
		t.Run("GET", func(t *testing.T) {
			req, err := httputil.NewRequestWithContext(ctx, http.MethodGet, srv.URL+path, nil)
			if err != nil {
				t.Fatal(err)
			}
			res, err := srv.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			got, want := res.StatusCode, http.StatusOK
			t.Logf("got: %d, want: %d", got, want)
			if got != want {
				t.Error()
			}
		})
	})
	t.Run("Report", func(t *testing.T) {
		ctx := zlog.Test(ctx, t)
		const path = `/index_report`
		t.Run("POST", func(t *testing.T) {
			const body = `{"hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000",` +
				`"layers":[{}]}`
			req, err := httputil.NewRequestWithContext(ctx, http.MethodPost, srv.URL+path, strings.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			res, err := srv.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			got, want := res.StatusCode, http.StatusCreated
			t.Logf("got: %d, want: %d", got, want)
			if got != want {
				t.Error()
			}
		})
		t.Run("DELETE", func(t *testing.T) {
			const body = `["sha256:0000000000000000000000000000000000000000000000000000000000000000"]`
			req, err := httputil.NewRequestWithContext(ctx, http.MethodDelete, srv.URL+path, strings.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			res, err := srv.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer res.Body.Close()
			var buf bytes.Buffer
			got, want := res.StatusCode, http.StatusOK
			t.Logf("got: %d, want: %d", got, want)
			if got != want {
				t.Error()
			}
			if _, err := io.Copy(&buf, res.Body); err != nil {
				t.Error(err)
			}
			// Should get back what we put in, so this is a little hack.
			if got, want := buf.String(), body; got != want {
				t.Errorf("got: %q, want: %q", got, want)
			}
		})
		t.Run("GET", func(t *testing.T) {
			req, err := httputil.NewRequestWithContext(ctx, http.MethodGet, srv.URL+path, nil)
			if err != nil {
				t.Fatal(err)
			}
			res, err := srv.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			got, want := res.StatusCode, http.StatusMethodNotAllowed
			t.Logf("got: %d, want: %d", got, want)
			if got != want {
				t.Error()
			}
		})
	})
	t.Run("ReportOne", func(t *testing.T) {
		ctx := zlog.Test(ctx, t)
		const path = `/index_report/sha256:0000000000000000000000000000000000000000000000000000000000000000`
		t.Run("DELETE", func(t *testing.T) {
			req, err := httputil.NewRequestWithContext(ctx, http.MethodDelete, srv.URL+path, nil)
			if err != nil {
				t.Fatal(err)
			}
			res, err := srv.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			got, want := res.StatusCode, http.StatusNoContent
			t.Logf("got: %d, want: %d", got, want)
			if got != want {
				t.Error()
			}
		})
		t.Run("GET", func(t *testing.T) {
			req, err := httputil.NewRequestWithContext(ctx, http.MethodGet, srv.URL+path, nil)
			if err != nil {
				t.Fatal(err)
			}
			res, err := srv.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			got, want := res.StatusCode, http.StatusOK
			t.Logf("got: %d, want: %d", got, want)
			if got != want {
				t.Error()
			}
		})
	})
	t.Run("AffectedManifests", func(t *testing.T) {
		ctx := zlog.Test(ctx, t)
		const path = `/internal/affected_manifest/`
		t.Run("POST", func(t *testing.T) {
			const body = `{"vulnerabilities":[]}`
			req, err := httputil.NewRequestWithContext(ctx, http.MethodPost, srv.URL+path, strings.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			res, err := srv.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			got, want := res.StatusCode, http.StatusOK
			t.Logf("got: %d, want: %d", got, want)
			if got != want {
				t.Error()
			}
		})
	})
}
