package health

import (
	"net/http"
	"sync/atomic"

	je "github.com/quay/claircore/pkg/jsonerr"
)

var ready *uint32 = new(uint32)

// Ready instructs the ReadinessHandler to begin serving 200OK status
func Ready() {
	atomic.StoreUint32(ready, uint32(1))
}

// NotReady instructs the ReadinessHandler to begin serving 503ServiceUnavailable status
func UnReady() {
	atomic.StoreUint32(ready, uint32(0))
}

// ReadinessHandler will return a 200OK or 503ServiceUnavailable status dependent
// on whether the exported Ready or NotReady methods have been called.
//
// The Ready() method must be called to begin returning 200OK
func ReadinessHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			resp := &je.Response{
				Code:    "method-not-allowed",
				Message: "endpoint only allows GET",
			}
			je.Error(w, resp, http.StatusMethodNotAllowed)
			return
		}

		ready := atomic.LoadUint32(ready)
		if ready == 1 {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		return
	}
}
