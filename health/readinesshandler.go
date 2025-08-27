package health

import (
	"net/http"
	"sync/atomic"
)

var ready atomic.Uint32

// Ready instructs the ReadinessHandler to begin serving 200 OK status.
func Ready() {
	ready.Store(uint32(1))
}

// Unready instructs the ReadinessHandler to begin serving 503
// Service Unavailable.
func Unready() {
	ready.Store(uint32(0))
}

// ReadinessHandler will return a 200 OK or 503 "Service Unavailable" status
// depending on whether the Ready or Unready functions have been called.
//
// The Ready() method must be called to begin returning 200 OK.
func ReadinessHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Content-Type", "text/plain; charset=utf-8")
		h.Set("Content-Length", "0")
		h.Set("Cache-Control", "no-store")
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		if ready.Load() != 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	})
}
