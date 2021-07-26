package rate

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sync/errgroup"
)

func noOpHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// mimic some work
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	})
}

func TestRateLimitMiddleWare(t *testing.T) {
	req, err := http.NewRequest("POST", "/indexer/api/v1/index_report", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	rlm := NewRateLimitMiddleware(1)
	handler := rlm.Handler("", noOpHandler())

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("handler did not return successful response as expected")
	}

	rr.Flush()
	var failures uint64

	eg := errgroup.Group{}
	for i := 0; i < 2; i++ {
		eg.Go(func() error {
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			if rr.Code != http.StatusOK {
				atomic.AddUint64(&failures, 1)
				return fmt.Errorf("Got status code %d", rr.Code)
			}
			return nil
		})
	}
	if err := eg.Wait(); err == nil || failures != 1 {
		t.Fatalf("test failed: expected one failure")
	}
}
