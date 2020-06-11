package httptransport

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"github.com/quay/clair/v4/matcher"
	je "github.com/quay/claircore/pkg/jsonerr"
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
		if param, ok := r.URL.Query()["prev"]; ok {
			if len(param) != 0 {
				prev, err = uuid.Parse(param[0])
				if err != nil {
					resp := &je.Response{
						Code:    "bad-request",
						Message: "could not parse \"prev\" query param into uuid",
					}
					je.Error(w, resp, http.StatusBadRequest)
					return
				}
			}
		}
		// cur param is required
		var cur uuid.UUID
		param, ok := r.URL.Query()["cur"]
		if !ok || len(param) == 0 {
			resp := &je.Response{
				Code:    "bad-request",
				Message: "\"cur\" query param is required",
			}
			je.Error(w, resp, http.StatusBadRequest)
			return
		}
		if cur, err = uuid.Parse(param[0]); err != nil {
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
		err = json.NewEncoder(w).Encode(&diff)
	}
}
