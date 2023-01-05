package webhook

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
	"github.com/quay/clair/config"
	"github.com/quay/zlog"

	"github.com/quay/clair/v4/notifier"
)

var (
	callback = "http://clair-notifier/notifier/api/v1/notification/"
	noteID   = uuid.New()
)

// TestDeliverer confirms the deliverer correctly sends the webhook
// data structure to the configured target.
func TestDeliverer(t *testing.T) {
	var whResult struct {
		sync.Mutex
		cb notifier.Callback
	}
	server := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			var cb notifier.Callback
			err := json.NewDecoder(r.Body).Decode(&cb)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			whResult.Lock()
			whResult.cb = cb
			whResult.Unlock()
		},
	))
	defer server.Close()
	ctx := zlog.Test(context.Background(), t)
	conf := config.Webhook{
		Callback: callback,
		Target:   server.URL,
	}

	d, err := New(&conf, server.Client(), nil)
	if err != nil {
		t.Fatalf("failed to create new webhook deliverer: %v", err)
	}
	err = d.Deliver(ctx, noteID)
	if err != nil {
		t.Fatalf("got: %v, wanted: nil", err)
	}

	whResult.Lock()
	wh := whResult.cb
	whResult.Unlock()

	if !cmp.Equal(wh.NotificationID, noteID) {
		t.Fatalf("got: %v, wanted: %v", wh.NotificationID, noteID)
	}

	cbURL, err := url.Parse(callback)
	if err != nil {
		t.Fatalf("failed to parse callback url: %v", err)
	}
	cbURL.Path = path.Join(cbURL.Path, noteID.String())

	if got, want := wh.Callback.String(), cbURL.String(); got != want {
		t.Fatalf("got: %v, wanted: %v", got, want)
	}
}
