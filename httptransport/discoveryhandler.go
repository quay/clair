package httptransport

import (
	"bytes"
	"context"
	_ "embed" // for json and etag
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/quay/zlog"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/quay/clair/v4/internal/httputil"
	"github.com/quay/clair/v4/middleware/compress"
)

//go:generate env -C api zsh ./openapi.zsh

var (
	//go:embed api/v1/openapi.json
	openapiJSON []byte
	//go:embed api/v1/openapi.yaml
	openapiYAML []byte
	//go:embed api/v1/openapi.etag
	openapiEtag string

	// Compacted version of [openapiJSON] for the wire.
	//
	// Doing this means we can keep a nicer-diffing version checked in.
	compactOpenapiJSON = sync.OnceValue(func() []byte {
		var buf bytes.Buffer
		buf.Grow(len(openapiJSON))
		if err := json.Compact(&buf, openapiJSON); err != nil {
			panic(err)
		}
		b := buf.Bytes()
		return slices.Clip(b)
	})
)

// DiscoveryHandler serves the embedded OpenAPI spec.
func DiscoveryHandler(_ context.Context, prefix string, topt otelhttp.Option) http.Handler {
	allow := []string{
		`application/openapi+json`, `application/openapi+yaml`, // New types: https://datatracker.ietf.org/doc/draft-ietf-httpapi-rest-api-mediatypes/
		`application/json`, `application/yaml`, // Format types.
		`application/vnd.oai.openapi+json`, `application/vnd.oai.openapi+yaml`, // Older vendor-tree types.
	}
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
		h := w.Header()
		kind := h.Get(`Content-Type`)
		var src *bytes.Reader
		switch kind[len(kind)-4:] {
		case "json":
			src = bytes.NewReader(compactOpenapiJSON())
		case "yaml":
			src = bytes.NewReader(openapiYAML)
		default:
			apiError(ctx, w, http.StatusInternalServerError, "unexpected error: unknown content-type kind: %q", kind)
		}
		h.Set("Etag", openapiEtag)
		var err error
		defer writerError(w, &err)()
		_, err = io.Copy(w, src)
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
