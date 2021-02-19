package httptransport

import (
	"net/http"

	"github.com/quay/claircore"
	"github.com/quay/claircore/pkg/jsonerr"
	"github.com/rs/zerolog"

	"github.com/quay/clair/v4/indexer"
	"github.com/quay/clair/v4/internal/codec"
)

func AffectedManifestHandler(serv indexer.Affected) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		log := zerolog.Ctx(ctx).With().
			Str("method", "index").
			Logger()
		ctx = log.WithContext(ctx)

		if r.Method != http.MethodPost {
			resp := &jsonerr.Response{
				Code:    "method-not-allowed",
				Message: "endpoint only allows POST",
			}
			jsonerr.Error(w, resp, http.StatusMethodNotAllowed)
			return
		}

		var vulnerabilities struct {
			V []claircore.Vulnerability `json:"vulnerabilities"`
		}
		dec := codec.GetDecoder(r.Body)
		defer codec.PutDecoder(dec)
		if err := dec.Decode(&vulnerabilities); err != nil {
			resp := &jsonerr.Response{
				Code:    "bad-request",
				Message: err.Error(),
			}
			jsonerr.Error(w, resp, http.StatusBadRequest)
			return
		}

		affected, err := serv.AffectedManifests(ctx, vulnerabilities.V)
		if err != nil {
			resp := &jsonerr.Response{
				Code:    "internal-server-error",
				Message: err.Error(),
			}
			jsonerr.Error(w, resp, http.StatusInternalServerError)
			return
		}

		defer writerError(w, &err)
		enc := codec.GetEncoder(w)
		defer codec.PutEncoder(enc)
		err = enc.Encode(affected)
		return
	}
}
