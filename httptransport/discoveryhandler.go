package httptransport

import (
	"bytes"
	"context"
	_ "embed" // for json and etag
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/quay/zlog"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/quay/clair/v4/internal/httputil"
	"github.com/quay/clair/v4/middleware/compress"
)

//go:generate go run openapigen.go

var (
	//go:embed openapi.json
	openapiJSON []byte
	//go:embed openapi.etag
	openapiJSONEtag string
)

// DiscoveryHandler serves the embedded OpenAPI spec.
func DiscoveryHandler(_ context.Context, prefix string, topt otelhttp.Option) http.Handler {
	allow := []string{`application/json`, `application/vnd.oai.openapi+json`}
	// These functions are written back-to-front.
	var inner http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		if r.Method != http.MethodGet {
			apiError(ctx, w, http.StatusMethodNotAllowed, "endpoint only allows GET")
		}
		switch err := pickContentType(w, r, allow); {
		case errors.Is(err, nil):
		case errors.Is(err, ErrMediaType):
			apiError(ctx, w, http.StatusUnsupportedMediaType, "unable to negotiate common media type for %v", allow)
		default:
			apiError(ctx, w, http.StatusInternalServerError, "unexpected error: %v", err)
		}
		w.Header().Set("etag", openapiJSONEtag)
		var err error
		defer writerError(w, &err)()
		_, err = io.Copy(w, bytes.NewReader(openapiJSON))
	})
	inner = otelhttp.NewHandler(
		compress.Handler(discoverywrapper.wrap(prefix, inner)),
		"discovery",
		otelhttp.WithMessageEvents(otelhttp.ReadEvents, otelhttp.WriteEvents),
		topt,
	)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		r = withRequestID(r)
		ctx := r.Context()
		var status int
		var length int64
		w = httputil.ResponseRecorder(&status, &length, w)
		defer func() {
			switch err := http.NewResponseController(w).Flush(); {
			case errors.Is(err, nil):
			case errors.Is(err, http.ErrNotSupported):
				// Skip
			default:
				zlog.Warn(ctx).
					Err(err).
					Msg("unable to flush http response")
			}
			zlog.Info(ctx).
				Str("remote_addr", r.RemoteAddr).
				Str("method", r.Method).
				Str("request_uri", r.RequestURI).
				Int("status", status).
				Int64("written", length).
				Dur("duration", time.Since(start)).
				Msg("handled HTTP request")
		}()
		inner.ServeHTTP(w, r)
	})
}

func init() {
	discoverywrapper.init("discovery")
}

var discoverywrapper wrapper
