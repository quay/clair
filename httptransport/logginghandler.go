package httptransport

import (
	"net/http"
	"strconv"
	"time"

	"github.com/rs/zerolog"
)

type httpStatusWriter struct {
	http.ResponseWriter
	StatusCode int
}

// LoggingHandler will log HTTP requests using the pre initialized zerolog.
func LoggingHandler(next http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		log := zerolog.Ctx(r.Context())

		// default HTTP StatusOK
		lrw := &httpStatusWriter{ResponseWriter: w, StatusCode: http.StatusOK}

		next.ServeHTTP(w, r)

		log.Info().
			Str("remote addr", r.RemoteAddr).
			Str("method", r.Method).
			Str("request uri", r.RequestURI).
			Str("status", strconv.Itoa(lrw.StatusCode)).
			Float64("elapsed time (md)", float64(time.Since(start).Nanoseconds())*1e-6).
			Msg("handled HTTP request")
	}
}
