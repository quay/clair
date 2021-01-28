package httptransport

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"testing"

	"github.com/quay/clair/v4/indexer"
	"github.com/quay/clair/v4/matcher"
	"github.com/quay/zlog"
	othttp "go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
)

// TestUpdateEndpoints registers the handlers and tests that they're registered
// at the correct endpoint.
func TestUpdateEndpoints(t *testing.T) {
	m := &matcher.Mock{}
	i := &indexer.Mock{}
	s := &Server{
		matcher:  m,
		indexer:  i,
		ServeMux: http.NewServeMux(),
		traceOpt: othttp.WithTracerProvider(otel.GetTracerProvider()),
	}
	ctx := zlog.Test(context.Background(), t)
	if err := s.configureMatcherMode(ctx); err != nil {
		t.Error(err)
	}

	srv := httptest.NewServer(s)
	defer srv.Close()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Error(err)
	}
	u.Path = path.Join(u.Path, UpdateOperationAPIPath, "")
	t.Log(u)

	res, err := srv.Client().Get(u.String())
	if err != nil {
		t.Error(err)
	}
	if got, want := res.StatusCode, http.StatusOK; got != want {
		t.Errorf("got: %v, want: %v", got, want)
	}
}
