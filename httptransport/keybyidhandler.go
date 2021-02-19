package httptransport

import (
	"errors"
	"net/http"
	"path"

	"github.com/google/uuid"
	je "github.com/quay/claircore/pkg/jsonerr"
	jose "gopkg.in/square/go-jose.v2"

	clairerror "github.com/quay/clair/v4/clair-error"
	"github.com/quay/clair/v4/internal/codec"
	"github.com/quay/clair/v4/notifier"
)

// KeyByIDHandler returns a particular key queried by ID in JWK format.
func KeyByIDHandler(keystore notifier.KeyStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			resp := &je.Response{
				Code:    "method-not-allowed",
				Message: "endpoint only allows GET",
			}
			je.Error(w, resp, http.StatusMethodNotAllowed)
			return
		}
		keyParam := path.Base(r.URL.Path)
		if keyParam == "" {
			resp := &je.Response{
				Code:    "bad-request",
				Message: "malformed path. must provide a key id",
			}
			je.Error(w, resp, http.StatusBadRequest)
			return
		}
		keyID, err := uuid.Parse(keyParam)
		if err != nil {
			resp := &je.Response{
				Code:    "bad-request",
				Message: "malformed path. could not parse into uuid: " + err.Error(),
			}
			je.Error(w, resp, http.StatusBadRequest)
			return
		}

		ctx := r.Context()
		k, err := keystore.KeyByID(ctx, keyID)
		switch {
		case errors.As(err, &clairerror.ErrKeyNotFound{}):
			resp := &je.Response{
				Code:    "not-found",
				Message: "the key id " + keyID.String() + " does not exist",
			}
			je.Error(w, resp, http.StatusNotFound)
			return
		case err == nil:
			// hop out
		default:
			resp := &je.Response{
				Code:    "internal-server-error",
				Message: err.Error(),
			}
			je.Error(w, resp, http.StatusInternalServerError)
			return

		}

		jwk := jose.JSONWebKey{
			Key:   k.Public,
			KeyID: k.ID.String(),
			Use:   "sig",
		}
		defer writerError(w, &err)()
		enc := codec.GetEncoder(w)
		defer codec.PutEncoder(enc)
		err = enc.Encode(&jwk)
	}
}
