package httptransport

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
	"github.com/quay/clair/v4/notifier"
	"github.com/quay/clair/v4/notifier/service"
	"github.com/quay/clair/v4/pkg/pager"
)

// TestUpdateOperationHandler is a parallel harness for testing a UpdateOperation handler.
func TestNotificationsHandler(t *testing.T) {
	t.Run("Methods", testNotificationsHandlerMethods)
	t.Run("Get", testNotificationHandlerGet)
	t.Run("GetParams", testNotificationHandlerGetParams)
	t.Run("Delete", testNotificationHandlerDelete)
}

// testNotificationHandlerDelete confirms the handler performs a delete
// correctly
func testNotificationHandlerDelete(t *testing.T) {
	t.Parallel()
	var (
		noteID = uuid.New()
	)

	nm := &service.Mock{
		DeleteNotifications_: func(ctx context.Context, id uuid.UUID) error {
			if !cmp.Equal(id, noteID) {
				t.Fatalf("got: %v, want: %v", id, noteID)
			}
			return nil
		},
	}

	h := NotificationHandler(nm)
	rr := httptest.NewRecorder()
	u, _ := url.Parse("http://clair-notifier/api/v1/notification/" + noteID.String())
	req := &http.Request{
		URL:    u,
		Method: http.MethodGet,
	}

	h.Delete(rr, req)
	res := rr.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("got: %v, wanted: %v", res.StatusCode, http.StatusOK)
	}
}

// testNotificationHandlerGetParams confirms the Get handler works correctly
func testNotificationHandlerGet(t *testing.T) {
	t.Parallel()
	var (
		nextID     = uuid.New()
		inPageWant = pager.Page{
			Size: 500,
		}
		noteID      = uuid.New()
		outPageWant = pager.Page{
			Size: 500,
			Next: &nextID,
		}
	)

	nm := &service.Mock{
		Notifications_: func(ctx context.Context, id uuid.UUID, page *pager.Page) ([]notifier.Notification, pager.Page, error) {
			if !cmp.Equal(id, noteID) {
				t.Fatalf("got: %v, wanted: %v", id, noteID)
			}
			if !cmp.Equal(page, &inPageWant) {
				t.Fatalf("got: %v, wanted: %v", page, inPageWant)
			}
			return []notifier.Notification{}, pager.Page{
				Size: inPageWant.Size,
				Next: &nextID,
			}, nil
		},
	}

	h := NotificationHandler(nm)
	rr := httptest.NewRecorder()
	u, _ := url.Parse("http://clair-notifier/api/v1/notification/" + noteID.String())
	req := &http.Request{
		URL:    u,
		Method: http.MethodGet,
	}

	h.Get(rr, req)
	res := rr.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("got: %v, wanted: %v", res.StatusCode, http.StatusOK)
	}
	var noteResp Response
	err := json.NewDecoder(res.Body).Decode(&noteResp)
	if err != nil {
		t.Fatalf("failed to deserialize notification response: %v", err)
	}

	if !cmp.Equal(noteResp.Page, outPageWant) {
		t.Fatalf("got: %v, want: %v", noteResp.Page, outPageWant)
	}
}

// testNotificationHandlerGetParams confirms the Get handler works correctly
// when parameters are present
func testNotificationHandlerGetParams(t *testing.T) {
	t.Parallel()
	const (
		pageSizeParam = "100"
		pageParam     = "10"
	)
	var (
		nextID     = uuid.New()
		inPageWant = pager.Page{
			Size: 100,
		}
		noteID      = uuid.New()
		outPageWant = pager.Page{
			Size: 100,
			Next: &nextID,
		}
	)

	nm := &service.Mock{
		Notifications_: func(ctx context.Context, id uuid.UUID, page *pager.Page) ([]notifier.Notification, pager.Page, error) {
			if !cmp.Equal(id, noteID) {
				t.Fatalf("got: %v, wanted: %v", id, noteID)
			}
			if !cmp.Equal(page, &inPageWant) {
				t.Fatalf("got: %v, wanted: %v", page, inPageWant)
			}
			return []notifier.Notification{}, pager.Page{
				Size: inPageWant.Size,
				Next: &nextID,
			}, nil
		},
	}

	h := NotificationHandler(nm)
	rr := httptest.NewRecorder()
	u, _ := url.Parse("http://clair-notifier/api/v1/notification/" + noteID.String())
	v := url.Values{}
	v.Set("page_size", pageSizeParam)
	v.Set("page", pageParam)
	u.RawQuery = v.Encode()
	req := &http.Request{
		URL:    u,
		Method: http.MethodGet,
	}

	h.Get(rr, req)
	res := rr.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("got: %v, wanted: %v", res.StatusCode, http.StatusOK)
	}
	var noteResp Response
	err := json.NewDecoder(res.Body).Decode(&noteResp)
	if err != nil {
		t.Fatalf("failed to deserialize notification response: %v", err)
	}

	if !cmp.Equal(noteResp.Page, outPageWant) {
		t.Fatalf("got: %v, want: %v", noteResp.Page, outPageWant)
	}
}

func testNotificationsHandlerMethods(t *testing.T) {
	t.Parallel()
	h := NotificationHandler(&service.Mock{})
	srv := httptest.NewServer(h)
	defer srv.Close()
	c := srv.Client()

	for _, m := range []string{
		http.MethodConnect,
		http.MethodHead,
		http.MethodOptions,
		http.MethodPatch,
		http.MethodPost,
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
