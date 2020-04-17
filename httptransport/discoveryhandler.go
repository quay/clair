package httptransport

import (
	"io"
	"net/http"

	je "github.com/quay/claircore/pkg/jsonerr"
)

//go:generate go run openapigen.go

// DiscoveryHandler serves the embedded OpenAPI spec.
func DiscoveryHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			resp := &je.Response{
				Code:    "method-not-allowed",
				Message: "endpoint only allows GET",
			}
			je.Error(w, resp, http.StatusMethodNotAllowed)
			return
		}
		ct := "application/vnd.oai.openapi+json"
		// Add a gate so that requesters expecting the yaml version get some
		// sort of error.
		if as, ok := r.Header["Accept"]; ok {
			bail := true
			for _, a := range as {
				if a == "application/json" ||
					a == "application/vnd.oai.openapi+json" {
					ct = a
					bail = false
					break
				}
			}
			if bail {
				resp := &je.Response{
					Code:    "unknown accept type",
					Message: "endpoint only allows application/json or application/vnd.oai.openapi+json",
				}
				je.Error(w, resp, http.StatusBadRequest)
				return
			}
		}
		w.Header().Add("content-type", ct)
		w.Header().Set("etag", _openapiJSONEtag)
		var err error
		defer writerError(w, &err)()
		_, err = io.WriteString(w, _openapiJSON)
	})
}
