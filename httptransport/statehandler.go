package httptransport

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"

	"github.com/quay/clair/v4/indexer"
	je "github.com/quay/claircore/pkg/jsonerr"
)

// StateHandler utilizes a Stater to report the
// curent runtime state of an Indexer.
//
// Indexers running with different scanner versions
// will produce unique states and indicate to clients
// a re-index is necessary.
func StateHandler(service indexer.Stater) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		ctx := r.Context()
		s, _ := service.State(ctx)
		tag := `"` + s + `"`
		w.Header().Add("etag", tag)

		es, ok := r.Header["If-None-Match"]
		if ok {
			if sort.Strings(es); sort.SearchStrings(es, tag) != -1 {
				w.WriteHeader(http.StatusNotModified)
				return
			}
		}
		w.Header().Set("content-type", "application/json")

		err := json.NewEncoder(w).Encode(struct {
			State string `json:"state"`
		}{
			State: s,
		})
		if err != nil {
			resp := &je.Response{
				Code:    "encoding-error",
				Message: fmt.Sprintf("failed to encode scan report: %v", err),
			}
			je.Error(w, resp, http.StatusInternalServerError)
		}
		return
	}
}
