package httptransport

import (
	"net/http"
	"time"

	"github.com/rs/zerolog"
)

type httpStatusWriter struct {
	http.ResponseWriter
	StatusCode int
}

func (lrw *httpStatusWriter) WriteHeader(code int) {
	lrw.StatusCode = code
	lrw.ResponseWriter.WriteHeader(code)
}

// LoggingHandler will log HTTP requests using the pre initialized zerolog.
func LoggingHandler(next http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		log := zerolog.Ctx(r.Context())

		// default HTTP StatusOK
		lrw := &httpStatusWriter{ResponseWriter: w, StatusCode: http.StatusOK}

		next.ServeHTTP(lrw, r)

		log.Info().
			Str("remote addr", r.RemoteAddr).
			Str("method", r.Method).
			Str("request uri", r.RequestURI).
			Int("status", lrw.StatusCode).
			Str("elapsed time (md)", time.Since(start).String()).
			Msg("handled HTTP request")
	}
}
