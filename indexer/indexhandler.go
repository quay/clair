package indexer

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/quay/claircore"
	je "github.com/quay/claircore/pkg/jsonerr"
)

// IndexHandler utilizes an Indexer to begin a
// Index of a manifest.
func IndexHandler(service Indexer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			resp := &je.Response{
				Code:    "method-not-allowed",
				Message: "endpoint only allows POST",
			}
			je.Error(w, resp, http.StatusMethodNotAllowed)
			return
		}

		ctx := r.Context()
		var m claircore.Manifest
		err := json.NewDecoder(r.Body).Decode(&m)
		if err != nil {
			resp := &je.Response{
				Code:    "bad-request",
				Message: fmt.Sprintf("failed to deserialize manifest: %v", err),
			}
			je.Error(w, resp, http.StatusBadRequest)
			return
		}

		// ToDo: manifest structure validation
		report, err := service.Index(ctx, &m)
		if err != nil {
			resp := &je.Response{
				Code:    "index-error",
				Message: fmt.Sprintf("failed to start scan: %v", err),
			}
			je.Error(w, resp, http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusCreated)
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
