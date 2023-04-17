package httptransport

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/quay/zlog"
	"golang.org/x/sync/semaphore"
)

var concurrentLimitedCounter = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Namespace: metricNamespace,
		Subsystem: metricSubsystem,
		Name:      "concurrencylimited_total",
		Help:      "Total number of requests that have been concurrency limited.",
	},
	[]string{"endpoint", "method"},
)

// LimitHandler is a wrapper to help with concurrency limiting. This is slightly
// more complicated than the naive approach to allow for filtering on multiple
// aspects of the request.
//
// "Check" and "Next" need to be populated.
type limitHandler struct {
	// The Check func inspects the request, and returns the semaphore to use and
	// the endpoint to use in metrics. If a nil is returned, the request is
	// allowed.
	Check func(*http.Request) (*semaphore.Weighted, string)
	// Next is the Handler to forward requests to, if allowed.
	Next http.Handler
}

func (l *limitHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sem, endpt := l.Check(r)
	if sem != nil {
		if !sem.TryAcquire(1) {
			concurrentLimitedCounter.WithLabelValues(endpt, r.Method).Add(1)
			ctx := r.Context()
			zlog.Info(ctx).
				Str("remote_addr", r.RemoteAddr).
				Str("method", r.Method).
				Str("request_uri", r.RequestURI).
				Int("status", http.StatusTooManyRequests).
				Msg("rate limited HTTP request")

			apiError(ctx, w, http.StatusTooManyRequests, "server handling too many requests")
		}
		defer sem.Release(1)
	}
	l.Next.ServeHTTP(w, r)
}
