package indexer

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/quay/claircore"
	je "github.com/quay/claircore/pkg/jsonerr"
)

// IndexReportHandler utilizes a Reporter to serialize
// and return a claircore.IndexReport given a path parameter
func IndexReportHandler(rep Reporter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			resp := &je.Response{
				Code:    "method-not-allowed",
				Message: "endpoint only allows GET",
			}
			je.Error(w, resp, http.StatusMethodNotAllowed)
			return
		}

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

		ctx := r.Context()
		report, ok, err := rep.IndexReport(ctx, manifest)
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

		err = json.NewEncoder(w).Encode(report)
		if err != nil {
			resp := &je.Response{
				Code:    "encoding-error",
				Message: fmt.Sprintf("failed to encode scan report: %v", err),
			}
			je.Error(w, resp, http.StatusInternalServerError)
			return
		}
	}
}
