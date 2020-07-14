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
	"github.com/quay/clair/v4/notifier"
	"github.com/quay/claircore/test/log"
)

var (
	callback = "http://clair-notifier/api/v1/notification"
	noteID   = uuid.New()
)

// TestDeliverer confirms the deliverer correctly sends the webhook
// datas structure to the configured target.
func TestDeliverer(t *testing.T) {
	var whResult struct {
		sync.Mutex
		cb notifier.Callback
	}
	var server *httptest.Server = httptest.NewServer(http.HandlerFunc(
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
			return
		},
	))
	ctx := log.TestLogger(context.Background(), t)
	conf := Config{
		Callback: callback,
		Target:   server.URL,
	}
	var err error
	conf, err = conf.Validate()
	if err != nil {
		t.Fatalf("failed to validate webhook config: %v", err)
	}

	d, err := New(conf, nil)
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

	if !cmp.Equal(wh.Callback, *cbURL) {
		t.Fatalf("got: %v, wanted: %v", wh.Callback, cbURL)
	}
}
