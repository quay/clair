package health

import (
	"net/http"

	"gocloud.dev/server/health"
)

func HealthHandler(checkers []health.Checker) http.Handler {
	h := &health.Handler{}
	for _, checker := range checkers {
		h.Add(checker)
	}
	return h
}

var CheckHandler = &health.Handler{}
