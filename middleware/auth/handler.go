package auth

import (
	"context"
	"net/http"
	"strings"
)

// AuthCheck is an interface that reports whether the passed request should be
// allowed to continue.
type AuthCheck interface {
	Check(context.Context, *http.Request) bool
}

type handler struct {
	auth AuthCheck
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
// the passed AuthCheck.
func Handler(h http.Handler, f AuthCheck) http.Handler {
	return &handler{
		auth: f,
		next: h,
	}
}

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
