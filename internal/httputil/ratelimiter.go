package httputil

import (
	"net/http"
	"sync"

	"golang.org/x/time/rate"
)

// RateLimiter wraps the provided RoundTripper with a limiter allowing 10
// requests/second/host.
//
// It responds to HTTP 429 responses by automatically decreasing the rate.
func RateLimiter(next http.RoundTripper) http.RoundTripper {
	return &ratelimiter{
		rt: next,
		lm: sync.Map{},
	}
}

// Ratelimiter implements the limiting by using a concurrent map and Limiter
// structs.
type ratelimiter struct {
	lm sync.Map
	rt http.RoundTripper
}

const rateCap = 10

// RoundTrip implements http.RoundTripper.
func (r *ratelimiter) RoundTrip(req *http.Request) (*http.Response, error) {
	key := req.URL.Host
	li, ok := r.lm.Load(key)
	if !ok {
		// Limiter allows "rateCap" per sec, one at a time.
		l := rate.NewLimiter(rate.Limit(rateCap), 1)
		li, _ = r.lm.LoadOrStore(key, l)
	}
	l := li.(*rate.Limiter)
	if err := l.Wait(req.Context()); err != nil {
		return nil, err
	}
	res, err := r.rt.RoundTrip(req)
	// This seems to be the contract that http.Transport implements.
	if err != nil {
		return nil, err
	}
	switch res.StatusCode {
	case http.StatusOK:
		// Try increasing on OK.
		if lim := l.Limit(); lim < rateCap {
			l.SetLimit(lim + 1)
		}
	case http.StatusTooManyRequests:
		// Try to allow some requests, eventually.
		l.SetLimit(detune(l.Limit()))
	}
	return res, nil
}

// Detune reduces the rate.
func detune(in rate.Limit) rate.Limit {
	if in <= 1 {
		return in / 2
	}
	return in - 1
}
