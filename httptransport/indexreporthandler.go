package httptransport

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/quay/claircore"
	je "github.com/quay/claircore/pkg/jsonerr"

	"github.com/quay/clair/v4/indexer"
	"github.com/quay/clair/v4/internal/codec"
)

// IndexReportHandler utilizes a Reporter to serialize
// and return a claircore.IndexReport given a path parameter
func IndexReportHandler(serv indexer.StateReporter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			resp := &je.Response{
				Code:    "method-not-allowed",
				Message: "endpoint only allows GET",
			}
			je.Error(w, resp, http.StatusMethodNotAllowed)
			return
		}
		ctx := r.Context()

		manifestStr := strings.TrimPrefix(r.URL.Path, IndexReportAPIPath)
		if manifestStr == "" {
			resp := &je.Response{
				Code:    "bad-request",
				Message: "malformed path. provide a single manifest hash",
			}
			je.Error(w, resp, http.StatusBadRequest)
			return
		}
		manifest, err := claircore.ParseDigest(manifestStr)
		if err != nil {
			resp := &je.Response{
				Code:    "bad-request",
				Message: "malformed path: " + err.Error(),
			}
			je.Error(w, resp, http.StatusBadRequest)
			return
		}

		state, err := serv.State(ctx)
		if err != nil {
			resp := &je.Response{
				Code:    "internal error",
				Message: "could not retrieve indexer state " + err.Error(),
			}
			je.Error(w, resp, http.StatusInternalServerError)
			return
		}
		validator := `"` + state + `"`
		if unmodified(r, validator) {
			w.WriteHeader(http.StatusNotModified)
			return
		}

		report, ok, err := serv.IndexReport(ctx, manifest)
		if !ok {
			resp := &je.Response{
				Code:    "not-found",
				Message: fmt.Sprintf("index report for manifest %q not found", manifest.String()),
			}
			je.Error(w, resp, http.StatusNotFound)
			return
		}
		if err != nil {
			resp := &je.Response{
				Code:    "internal-server-error",
				Message: err.Error(),
			}
			je.Error(w, resp, http.StatusInternalServerError)
			return
		}

		w.Header().Add("etag", validator)
		defer writerError(w, &err)()
		enc := codec.GetEncoder(w)
		defer codec.PutEncoder(enc)
		err = enc.Encode(report)
	}
}
