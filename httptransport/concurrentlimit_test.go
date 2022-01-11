package httptransport

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"golang.org/x/sync/semaphore"
)

func TestConcurrentRequests(t *testing.T) {
	sem := semaphore.NewWeighted(1)
	// Ret controls when the http server returns.
	// Ready is strobed once the first request is seen.
	ret, ready := make(chan struct{}), make(chan struct{})
	ct := new(int64)
	var once sync.Once
	srv := httptest.NewServer(&limitHandler{
		Check: func(_ *http.Request) (*semaphore.Weighted, string) {
			return sem, ""
		},
		Next: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			atomic.AddInt64(ct, 1)
			once.Do(func() { close(ready) })
			<-ret
			w.WriteHeader(http.StatusNoContent)
		}),
	})
	defer srv.Close()
	c := srv.Client()

	ctx := context.Background()
	done := make(chan struct{})
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Long-poll goroutine.
	go func() {
		defer close(done)
		res, err := c.Do(req)
		if err != nil {
			t.Error(err)
			return
		}
		defer res.Body.Close()
		if got, want := res.StatusCode, http.StatusNoContent; got != want {
			t.Errorf("got: %d, want: %d", got, want)
		}
	}()

	// Wait for the above goroutine to hit the handler.
	<-ready
	for i := 0; i < 10; i++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
		if err != nil {
			t.Errorf("%d: %v", i, err)
		}
		res, err := c.Do(req)
		if err != nil {
			t.Errorf("%d: %v", i, err)
		}
		res.Body.Close()
		if got, want := res.StatusCode, http.StatusTooManyRequests; got != want {
			t.Errorf("got: %d, want: %d", got, want)
		}
	}
	close(ret)
	<-done
	if got, want := *ct, int64(1); got != want {
		t.Errorf("got: %d requests, want: %d requests", got, want)
	}
}
