package httptransport

import (
	"fmt"
	"net/http"

	"github.com/google/uuid"
	je "github.com/quay/claircore/pkg/jsonerr"

	"github.com/quay/clair/v4/internal/codec"
	"github.com/quay/clair/v4/matcher"
)

// UpdateDiffHandler provides an endpoint to GET update diffs
// when provided an UpdateOperation ref.
func UpdateDiffHandler(serv matcher.Differ) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		if r.Method != http.MethodGet {
			resp := &je.Response{
				Code:    "method-not-allowed",
				Message: "endpoint only allows GET",
			}
			je.Error(w, resp, http.StatusMethodNotAllowed)
			return
		}
		// prev param is optional.
		var prev uuid.UUID
		var err error
		if param := r.URL.Query().Get("prev"); param != "" {
			prev, err = uuid.Parse(param)
			if err != nil {
				resp := &je.Response{
					Code:    "bad-request",
					Message: "could not parse \"prev\" query param into uuid",
				}
				je.Error(w, resp, http.StatusBadRequest)
				return
			}
		}

		// cur param is required
		var cur uuid.UUID
		var param string
		if param = r.URL.Query().Get("cur"); param == "" {
			resp := &je.Response{
				Code:    "bad-request",
				Message: "\"cur\" query param is required",
			}
			je.Error(w, resp, http.StatusBadRequest)
			return
		}
		if cur, err = uuid.Parse(param); err != nil {
			resp := &je.Response{
				Code:    "bad-request",
				Message: "could not parse \"cur\" query param into uuid",
			}
			je.Error(w, resp, http.StatusBadRequest)
			return
		}

		diff, err := serv.UpdateDiff(ctx, prev, cur)
		if err != nil {
			resp := &je.Response{
				Code:    "internal server error",
				Message: fmt.Sprintf("could not get update operations: %v", err),
			}
			je.Error(w, resp, http.StatusInternalServerError)
			return
		}

		defer writerError(w, &err)()
		enc := codec.GetEncoder(w)
		defer codec.PutEncoder(enc)
		err = enc.Encode(&diff)
	}
}
