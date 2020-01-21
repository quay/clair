package main

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

type authHandler struct {
	auth AuthCheck
	next http.Handler
}

func (h *authHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !h.auth.Check(r.Context(), r) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	h.next.ServeHTTP(w, r)
}

// AuthHandler returns a Handler that gates access to the passed Handler behind
// the passed AuthCheck.
func AuthHandler(h http.Handler, f AuthCheck) http.Handler {
	return &authHandler{
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
