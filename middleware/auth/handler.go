package auth

import (
	"context"
	"net/http"
	"strings"
)

// Checker is an interface that reports whether the passed request should be
// allowed to continue.
type Checker interface {
	Check(context.Context, *http.Request) bool
}

type handler struct {
	auth Checker
	next http.Handler
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !h.auth.Check(r.Context(), r) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	h.next.ServeHTTP(w, r)
}

// Handler returns a http.Handler that gates access to the passed Handler behind
// the passed Checker.
func Handler(h http.Handler, f ...Checker) http.Handler {
	r := &handler{
		auth: fail{},
		next: h,
	}
	if len(f) == 1 {
		r.auth = f[0]
	} else {
		r.auth = any(f)
	}
	return r
}

// Any attempts all Checkers in order and reports true if any succeeds.
type any []Checker

// Check implements Checker.
func (a any) Check(ctx context.Context, r *http.Request) bool {
	for _, c := range a {
		if ok := c.Check(ctx, r); ok {
			return true
		}
	}
	return false
}

// Fail is a Checker that always fails.
type fail struct{}

// Check implements Checker.
func (fail) Check(_ context.Context, _ *http.Request) bool { return false }

func fromHeader(r *http.Request) (string, bool) {
	hs, ok := r.Header["Authorization"]
	if !ok {
		return "", false
	}
	for _, h := range hs {
		if strings.HasPrefix(h, "Bearer ") {
			return strings.TrimPrefix(h, "Bearer "), true
		}
	}
	return "", false
}
