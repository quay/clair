package rate

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/quay/claircore/pkg/jsonerr"
)

var (
	rateLimitedCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "clair",
			Subsystem: "http",
			Name:      "ratelimited_total",
			Help:      "Total number of requests that have been rate limited.",
		},
		[]string{"endpoint"},
	)
)

type RateLimitMiddleware struct {
	ctlChan chan struct{}
}

func NewRateLimitMiddleware(maxConcurrent int) *RateLimitMiddleware {
	rlm := &RateLimitMiddleware{}
	if maxConcurrent > 0 {
		rlm.ctlChan = make(chan struct{}, maxConcurrent)
	}
	return rlm
}

func (rlm *RateLimitMiddleware) Handler(endpoint string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// If the channel is never initialized just carry on.
		if rlm.ctlChan == nil {
			next.ServeHTTP(w, r)
			return
		}

		// See if we have any space for a new request.
		select {
		case rlm.ctlChan <- struct{}{}:
			defer func() { <-rlm.ctlChan }()
		default:
			rateLimitedCounter.WithLabelValues(endpoint).Add(1)
			resp := &jsonerr.Response{
				Code:    "too-many-requests",
				Message: "server handling too many requests",
			}
			jsonerr.Error(w, resp, http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
		// Bug (crozzy): this approach is a little rough and
		// will lock-out indexing for pre-indexed images, which
		// is not resource intensive.
	})
}

func (rlm *RateLimitMiddleware) Close() {
	close(rlm.ctlChan)
	rlm.ctlChan = nil
}
