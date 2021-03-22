package httputil

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestRate(t *testing.T) {
	const nReq = 20

	var wg sync.WaitGroup
	wg.Add(nReq)
	begin := make(chan struct{})
	var last struct {
		sync.Mutex
		t time.Time
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		last.Lock()
		last.t = time.Now()
		last.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	cl := srv.Client()
	cl.Transport = RateLimiter(cl.Transport)

	for i := 0; i < nReq; i++ {
		go func() {
			defer wg.Done()
			<-begin
			res, err := cl.Get(srv.URL)
			if err != nil {
				t.Error(err)
				return
			}
			res.Body.Close()
		}()
	}

	first := time.Now()
	close(begin)
	wg.Wait()

	t.Logf("begin: %v", first)
	t.Logf("end:   %v", last.t)
	rate := nReq / last.t.Sub(first).Seconds()
	t.Logf("rate:  %v", rate)

	if rate < (rateCap-1) || rate > (rateCap+1) {
		t.Error("rate outside acceptable bounds")
	}
}
