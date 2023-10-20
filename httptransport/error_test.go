package httptransport

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/quay/zlog"

	"github.com/quay/clair/v4/internal/httputil"
)

func TestClientDisconnect(t *testing.T) {
	var status int
	// Bunch of sequencing events:
	reqStart := make(chan struct{})
	reqDone := make(chan struct{})
	handlerDone := make(chan struct{})

	// Server side:
	//	- Emit reqStart once the request is received.
	//	- Emit handlerDone once the request is done and "status" should be populated.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() { close(handlerDone) }()
		w = httputil.ResponseRecorder(&status, nil, w)
		ctx := zlog.Test(r.Context(), t) // The error handler emits logs.
		close(reqStart)
		<-ctx.Done()
		apiError(ctx, w, http.StatusOK, "hello from the handler")
	}))
	t.Cleanup(srv.Close)

	ctx, done := context.WithCancel(context.Background())
	// Closing "done" will cancel the client connection.
	req, err := http.NewRequestWithContext(ctx, "GET", srv.URL+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	// Emit reqDone when the client connection is done.
	go func() {
		_, err = srv.Client().Do(req)
		close(reqDone)
	}()

	<-reqStart
	done()
	<-reqDone
	t.Logf("got request error: %v", err)
	if err == nil {
		t.Error("expected non-nil error")
	}

	<-handlerDone
	if got, want := status, statusClientClosedRequest; got != want {
		t.Errorf("bad status code recorded: got: %d, want: %d", got, want)
	}
}
