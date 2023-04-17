package httptransport

import (
	"bytes"
	_ "embed" // for json and etag
	"errors"
	"io"
	"net/http"
)

//go:generate go run openapigen.go

var (
	//go:embed openapi.json
	openapiJSON []byte
	//go:embed openapi.etag
	openapiJSONEtag string
)

// DiscoveryHandler serves the embedded OpenAPI spec.
func DiscoveryHandler() http.Handler {
	allow := []string{`application/json`, `application/vnd.oai.openapi+json`}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
}
