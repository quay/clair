package httptransport

import (
	"net/http"

	je "github.com/quay/claircore/pkg/jsonerr"

	"github.com/quay/clair/v4/indexer"
	"github.com/quay/clair/v4/internal/codec"
)

// IndexStateHandler utilizes a Stater to report the
// curent runtime state of an Indexer.
//
// Indexers running with different scanner versions
// will produce unique states and indicate to clients
// a re-index is necessary.
func IndexStateHandler(service indexer.Stater) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		ctx := r.Context()
		s, err := service.State(ctx)
		if err != nil {
			resp := &je.Response{
				Code:    "internal error",
				Message: "could not retrieve indexer state " + err.Error(),
			}
			je.Error(w, resp, http.StatusInternalServerError)
			return
		}

		tag := `"` + s + `"`
		w.Header().Add("etag", tag)

		if unmodified(r, tag) {
			w.WriteHeader(http.StatusNotModified)
			return
		}

		w.Header().Set("content-type", "application/json")

		defer writerError(w, &err)()
		enc := codec.GetEncoder(w)
		defer codec.PutEncoder(enc)
		err = enc.Encode(struct {
			State string `json:"state"`
		}{
			State: s,
		})
	}
}
