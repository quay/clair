package httptransport

import (
	"errors"
	"io"
	"net/http"
	"strings"

	je "github.com/quay/claircore/pkg/jsonerr"
)

//go:generate go run openapigen.go

// DiscoveryHandler serves the embedded OpenAPI spec.
func DiscoveryHandler() http.Handler {
	allow := []string{`application/json`, `application/vnd.oai.openapi+json`}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			resp := &je.Response{
				Code:    "method-not-allowed",
				Message: "endpoint only allows GET",
			}
			je.Error(w, resp, http.StatusMethodNotAllowed)
			return
		}
		switch err := pickContentType(w, r, allow); {
		case errors.Is(err, nil):
		case errors.Is(err, ErrMediaType):
			resp := &je.Response{
				Code:    "unknown accept type",
				Message: "endpoint only allows " + strings.Join(allow, " or "),
			}
			je.Error(w, resp, http.StatusUnsupportedMediaType)
			return
		default:
			resp := &je.Response{
				Code:    "unknown other error",
				Message: err.Error(),
			}
			je.Error(w, resp, http.StatusBadRequest)
			return
		}
		w.Header().Set("etag", _openapiJSONEtag)
		var err error
		defer writerError(w, &err)()
		_, err = io.WriteString(w, _openapiJSON)
	})
}
