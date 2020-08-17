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
	"github.com/quay/claircore/test/log"
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
			ops:        func(context.Context, ...string) (map[string][]driver.UpdateOperation, error) { return nil, nil },
			latestOp:   func(context.Context) (uuid.UUID, error) { return uuid.Nil, nil },
			latestOps:  func(context.Context) (map[string][]driver.UpdateOperation, error) { return nil, nil },
			updateDiff: func(context.Context, uuid.UUID, uuid.UUID) (*driver.UpdateDiff, error) { return nil, nil },
		},
	}
}

func newTestIndexer() *indexerMock {
	return &indexerMock{
		index: func(ctx context.Context, manifest *claircore.Manifest) (*claircore.IndexReport, error) {
			return nil, nil
		},
		report: func(ctx context.Context, digest claircore.Digest) (*claircore.IndexReport, bool, error) {
			return nil, true, nil
		},
		state: func(ctx context.Context) (string, error) { return "", nil },
		affected: func(ctx context.Context, vulns []claircore.Vulnerability) (claircore.AffectedManifests, error) {
			return claircore.NewAffectedManifests(), nil
		},
	}
}

// TestUpdateEndpoints registers the handlers and tests that they're registered
// at the correct endpoint.
func TestUpdateEndpoints(t *testing.T) {
	m := newTestMatcher()
	i := newTestIndexer()
	s := &Server{
		matcher:  m,
		indexer:  i,
		ServeMux: http.NewServeMux(),
		traceOpt: othttp.WithTracer(global.TraceProvider().Tracer("clair")),
	}
	ctx := log.TestLogger(context.Background(), t)
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
