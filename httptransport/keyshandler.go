package httptransport

import (
	"net/http"

	je "github.com/quay/claircore/pkg/jsonerr"
	jose "gopkg.in/square/go-jose.v2"

	"github.com/quay/clair/v4/internal/codec"
	"github.com/quay/clair/v4/notifier"
)

// KeysHandler returns all keys persisted in the keystore in JWK set format.
func KeysHandler(keystore notifier.KeyStore) http.HandlerFunc {
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
		keys, err := keystore.Keys(ctx)
		if err != nil {
			resp := &je.Response{
				Code:    "internal-server-error",
				Message: err.Error(),
			}
			je.Error(w, resp, http.StatusInternalServerError)
			return
		}

		set := jose.JSONWebKeySet{
			Keys: make([]jose.JSONWebKey, 0, len(keys)),
		}
		for _, k := range keys {
			if err := ctx.Err(); err != nil {
				resp := &je.Response{
					Code:    "internal-server-error",
					Message: "internal server errror",
				}
				je.Error(w, resp, http.StatusInternalServerError)
				return
			}
			jwk := jose.JSONWebKey{
				Key:   k.Public,
				KeyID: k.ID.String(),
				Use:   "sig",
			}
			set.Keys = append(set.Keys, jwk)
		}

		defer writerError(w, &err)()
		enc := codec.GetEncoder(w)
		defer codec.PutEncoder(enc)
		err = enc.Encode(&set)
	}
}
