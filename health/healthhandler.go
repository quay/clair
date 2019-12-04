package health

import (
	"encoding/json"
	"fmt"
	"net/http"

	je "github.com/quay/claircore/pkg/jsonerr"
)

type DiagMsg struct {
	Version string
}

// HealthHandler returns a DiagMsg and a 200 status on request
func HealthHandler(msg DiagMsg) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			resp := &je.Response{
				Code:    "method-not-allowed",
				Message: "endpoint only allows POST",
			}
			je.Error(w, resp, http.StatusMethodNotAllowed)
			return
		}

		err := json.NewEncoder(w).Encode(&msg)
		if err != nil {
			resp := &je.Response{
				Code:    "internal-server-error",
				Message: fmt.Sprintf("failed to deserialize manifest: %v", err),
			}
			je.Error(w, resp, http.StatusInternalServerError)
			return
		}

		return
	}
}
