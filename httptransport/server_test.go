package httptransport

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"testing"

	"github.com/google/uuid"
	"github.com/quay/clair/config"
	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/zlog"

	"github.com/quay/clair/v4/indexer"
	"github.com/quay/clair/v4/matcher"
)

// TestUpdateEndpoints registers the handlers and tests that they're registered
// at the correct endpoint.
func TestUpdateEndpoints(t *testing.T) {
	m := &matcher.Mock{
		DeleteUpdateOperations_: func(context.Context, ...uuid.UUID) (int64, error) { return 0, nil },
		UpdateOperations_: func(context.Context, driver.UpdateKind, ...string) (map[string][]driver.UpdateOperation, error) {
			return nil, nil
		},
		LatestUpdateOperation_:  func(context.Context, driver.UpdateKind) (uuid.UUID, error) { return uuid.Nil, nil },
		LatestUpdateOperations_: func(context.Context, driver.UpdateKind) (map[string][]driver.UpdateOperation, error) { return nil, nil },
		UpdateDiff_:             func(context.Context, uuid.UUID, uuid.UUID) (*driver.UpdateDiff, error) { return nil, nil },
		Scan_:                   func(context.Context, *claircore.IndexReport) (*claircore.VulnerabilityReport, error) { return nil, nil },
	}
	i := &indexer.Mock{
		Index_: func(ctx context.Context, manifest *claircore.Manifest) (*claircore.IndexReport, error) {
			return nil, nil
		},
		IndexReport_: func(ctx context.Context, digest claircore.Digest) (*claircore.IndexReport, bool, error) {
			return nil, true, nil
		},
		State_: func(ctx context.Context) (string, error) { return "", nil },
		AffectedManifests_: func(ctx context.Context, vulns []claircore.Vulnerability) (*claircore.AffectedManifests, error) {
			return nil, nil
		},
	}
	ctx := zlog.Test(context.Background(), t)
	h, err := New(ctx, &config.Config{Mode: config.MatcherMode}, i, m, nil)
	if err != nil {
		t.Error(err)
	}
	srv := httptest.NewUnstartedServer(h)
	srv.Config.BaseContext = func(_ net.Listener) context.Context {
		return ctx
	}
	srv.Start()
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
