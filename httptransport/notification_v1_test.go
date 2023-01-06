package httptransport

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
	"github.com/quay/zlog"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/trace"

	"github.com/quay/clair/v4/internal/httputil"
	"github.com/quay/clair/v4/notifier"
	"github.com/quay/clair/v4/notifier/service"
)

// TestUpdateOperationHandler is a parallel harness for testing a UpdateOperation handler.
func TestNotificationsHandler(t *testing.T) {
	ctx := zlog.Test(context.Background(), t)
	t.Run("Methods", testNotificationsHandlerMethods(ctx))
	t.Run("Get", testNotificationHandlerGet(ctx))
	t.Run("GetParams", testNotificationHandlerGetParams(ctx))
	t.Run("Delete", testNotificationHandlerDelete(ctx))
}

var notifierTraceOpt = otelhttp.WithTracerProvider(trace.NewNoopTracerProvider())

// testNotificationHandlerDelete confirms the handler performs a delete
// correctly
func testNotificationHandlerDelete(ctx context.Context) func(*testing.T) {
	return func(t *testing.T) {
		t.Parallel()
		ctx := zlog.Test(ctx, t)
		noteID := uuid.New()

		nm := &service.Mock{
			DeleteNotifications_: func(ctx context.Context, id uuid.UUID) error {
				if !cmp.Equal(id, noteID) {
					t.Fatalf("got: %v, want: %v", id, noteID)
				}
				return nil
			},
		}

		h, err := NewNotificationV1(ctx, `/notifier/api/v1/`, nm, notifierTraceOpt)
		if err != nil {
			t.Error(err)
		}
		rr := httptest.NewRecorder()
		u, _ := url.Parse("http://clair-notifier/notifier/api/v1/notification/" + noteID.String())
		req, err := httputil.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			t.Error(err)
		}

		h.delete(rr, req)
		res := rr.Result()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("got: %v, wanted: %v", res.StatusCode, http.StatusOK)
		}
	}
}

// testNotificationHandlerGet confirms the Get handler works correctly
func testNotificationHandlerGet(ctx context.Context) func(*testing.T) {
	return func(t *testing.T) {
		t.Parallel()
		ctx := zlog.Test(ctx, t)
		var (
			nextID     = uuid.New()
			inPageWant = notifier.Page{
				Size: 500,
			}
			noteID      = uuid.New()
			outPageWant = notifier.Page{
				Size: 500,
				Next: &nextID,
			}
		)

		nm := &service.Mock{
			Notifications_: func(ctx context.Context, id uuid.UUID, page *notifier.Page) ([]notifier.Notification, notifier.Page, error) {
				if !cmp.Equal(id, noteID) {
					t.Fatalf("got: %v, wanted: %v", id, noteID)
				}
				if !cmp.Equal(page, &inPageWant) {
					t.Fatalf("got: %v, wanted: %v", page, inPageWant)
				}
				return []notifier.Notification{}, notifier.Page{
					Size: inPageWant.Size,
					Next: &nextID,
				}, nil
			},
		}

		h, err := NewNotificationV1(ctx, `/notifier/api/v1/`, nm, notifierTraceOpt)
		if err != nil {
			t.Error(err)
		}
		rr := httptest.NewRecorder()
		u, _ := url.Parse("http://clair-notifier/notifier/api/v1/notification/" + noteID.String())
		req, err := httputil.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			t.Error(err)
		}

		h.get(rr, req)
		res := rr.Result()
		if res.StatusCode != http.StatusOK {
			t.Errorf("got: %v, wanted: %v", res.StatusCode, http.StatusOK)
		}
		var noteResp notificationResponse
		if err := json.NewDecoder(res.Body).Decode(&noteResp); err != nil {
			t.Errorf("failed to deserialize notification response: %v", err)
		}
		if !cmp.Equal(noteResp.Page, outPageWant) {
			t.Errorf("got: %v, want: %v", noteResp.Page, outPageWant)
		}
	}
}

// testNotificationHandlerGetParams confirms the Get handler works correctly
// when parameters are present
func testNotificationHandlerGetParams(ctx context.Context) func(*testing.T) {
	return func(t *testing.T) {
		t.Parallel()
		ctx := zlog.Test(ctx, t)
		const (
			pageSizeParam = "100"
			pageParam     = "10"
		)
		var (
			nextID     = uuid.New()
			inPageWant = notifier.Page{
				Size: 100,
			}
			noteID      = uuid.New()
			outPageWant = notifier.Page{
				Size: 100,
				Next: &nextID,
			}
		)

		nm := &service.Mock{
			Notifications_: func(ctx context.Context, id uuid.UUID, page *notifier.Page) ([]notifier.Notification, notifier.Page, error) {
				if !cmp.Equal(id, noteID) {
					t.Fatalf("got: %v, wanted: %v", id, noteID)
				}
				if !cmp.Equal(page, &inPageWant) {
					t.Fatalf("got: %v, wanted: %v", page, inPageWant)
				}
				return []notifier.Notification{}, notifier.Page{
					Size: inPageWant.Size,
					Next: &nextID,
				}, nil
			},
		}

		h, err := NewNotificationV1(ctx, `/notifier/api/v1/`, nm, notifierTraceOpt)
		if err != nil {
			t.Error(err)
		}
		rr := httptest.NewRecorder()
		u, _ := url.Parse("http://clair-notifier/notifier/api/v1/notification/" + noteID.String())
		v := url.Values{}
		v.Set("page_size", pageSizeParam)
		v.Set("page", pageParam)
		u.RawQuery = v.Encode()
		req, err := httputil.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			t.Error(err)
		}

		h.get(rr, req)
		res := rr.Result()
		if res.StatusCode != http.StatusOK {
			t.Errorf("got: %v, wanted: %v", res.StatusCode, http.StatusOK)
		}
		var noteResp notificationResponse
		if err := json.NewDecoder(res.Body).Decode(&noteResp); err != nil {
			t.Errorf("failed to deserialize notification response: %v", err)
		}
		if !cmp.Equal(noteResp.Page, outPageWant) {
			t.Errorf("got: %v, want: %v", noteResp.Page, outPageWant)
		}
	}
}

func testNotificationsHandlerMethods(ctx context.Context) func(*testing.T) {
	return func(t *testing.T) {
		t.Parallel()
		ctx := zlog.Test(ctx, t)
		h, err := NewNotificationV1(ctx, `/notifier/api/v1/`, &service.Mock{}, notifierTraceOpt)
		if err != nil {
			t.Error(err)
		}
		srv := httptest.NewUnstartedServer(h)
		srv.Config.BaseContext = func(_ net.Listener) context.Context { return ctx }
		srv.Start()
		defer srv.Close()
		c := srv.Client()
		u := srv.URL + `/notifier/api/v1/notification/` + uuid.Nil.String()

		for _, m := range []string{
			http.MethodConnect,
			http.MethodHead,
			http.MethodOptions,
			http.MethodPatch,
			http.MethodPost,
			http.MethodPut,
			http.MethodTrace,
		} {
			req, err := httputil.NewRequestWithContext(ctx, m, u, nil)
			if err != nil {
				t.Fatalf("failed to create request: %v", err)
			}
			resp, err := c.Do(req)
			if err != nil {
				t.Fatalf("failed to make request: %v", err)
			}
			if resp.StatusCode != http.StatusMethodNotAllowed {
				t.Errorf("method: %v got: %v want: %v", m, resp.Status, http.StatusMethodNotAllowed)
			}
		}
	}
}
