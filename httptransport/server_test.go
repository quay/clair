package httptransport

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"testing"

	"github.com/google/uuid"
	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
	"go.opentelemetry.io/otel/api/global"
	"go.opentelemetry.io/otel/plugin/othttp"
)

type testMatcher struct {
	scanner
	differ
}

// NewTestMatcher returns a testMatcher with all functions set to non-nil stubs.
func newTestMatcher() *testMatcher {
	return &testMatcher{
		scanner: scanner{
			scan: func(context.Context, *claircore.IndexReport) (*claircore.VulnerabilityReport, error) { return nil, nil },
		},
		differ: differ{
			delete:     func(context.Context, ...uuid.UUID) error { return nil },
			latest:     func(context.Context) (uuid.UUID, error) { return uuid.Nil, nil },
			latestOps:  func(context.Context) (map[string]uuid.UUID, error) { return nil, nil },
			updateDiff: func(context.Context, uuid.UUID, uuid.UUID) (*driver.UpdateDiff, error) { return nil, nil },
		},
	}
}

type scanner struct {
	scan func(context.Context, *claircore.IndexReport) (*claircore.VulnerabilityReport, error)
}

func (s *scanner) Scan(ctx context.Context, ir *claircore.IndexReport) (*claircore.VulnerabilityReport, error) {
	return s.scan(ctx, ir)
}

// TestUpdateEndpoints registers the handlers and tests that they're registered
// at the correct endpoint.
func TestUpdateEndpoints(t *testing.T) {
	m := newTestMatcher()
	s := &Server{
		matcher:  m,
		ServeMux: http.NewServeMux(),
		traceOpt: othttp.WithTracer(global.TraceProvider().Tracer("clair")),
	}
	if err := s.configureUpdateEndpoints(); err != nil {
		t.Error(err)
	}

	srv := httptest.NewServer(s)
	defer srv.Close()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Error(err)
	}
	u.Path = path.Join(u.Path, internalRoot, "updates", "")
	t.Log(u)

	res, err := srv.Client().Get(u.String())
	if err != nil {
		t.Error(err)
	}
	if got, want := res.StatusCode, http.StatusOK; got != want {
		t.Errorf("got: %v, want: %v", got, want)
	}
}
