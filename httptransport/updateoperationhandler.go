package httptransport

import (
	"fmt"
	"net/http"
	"path/filepath"
	"strconv"

	"github.com/google/uuid"
	"github.com/quay/claircore/libvuln/driver"
	je "github.com/quay/claircore/pkg/jsonerr"
	"github.com/rs/zerolog"

	"github.com/quay/clair/v4/internal/codec"
	"github.com/quay/clair/v4/matcher"
)

var _ http.Handler = (*UOHandler)(nil)

// UOHandler implements http.Handler and provides http.HandlerFunc(s)
// for GET and DELETE operations.
type UOHandler struct {
	serv matcher.Differ
}

// UpdateOperationHandler creates a new UOHandler
func UpdateOperationHandler(serv matcher.Differ) *UOHandler {
	return &UOHandler{
		serv: serv,
	}
}

// ServeHTTP provides GET and DELETE operations for UpdateOperation models.
//
// Implements http.Handler interface and may also be used as a http.HandlerFunc
func (h *UOHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.Get(w, r)
	case http.MethodDelete:
		h.Delete(w, r)
	default:
		resp := &je.Response{
			Code:    "method-not-allowed",
			Message: "endpoint only allows POST",
		}
		je.Error(w, resp, http.StatusMethodNotAllowed)
	}
}

// Get retrieves UpdateOperation models.
//
// Supports conditional requests by providing the newest UpdateOperation as
// an etag.

// Clients may provide an 'If-None-Match' header with the etag value to receive
// a StatusNotModified when no new UpdateOperations have been created.
func (h *UOHandler) Get(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	// handle conditional request. this is an optimization
	if ref, err := h.serv.LatestUpdateOperation(ctx); err == nil {
		validator := `"` + ref.String() + `"`
		if unmodified(r, validator) {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("etag", validator)
	}

	latest := r.URL.Query().Get("latest")

	var uos map[string][]driver.UpdateOperation
	var err error
	if b, _ := strconv.ParseBool(latest); b {
		uos, err = h.serv.LatestUpdateOperations(ctx)
	} else {
		uos, err = h.serv.UpdateOperations(ctx)
	}
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
	err = enc.Encode(&uos)
}

// Delete removes an UpdateOperation models from the system.
func (h *UOHandler) Delete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := zerolog.Ctx(ctx)
	path := r.URL.Path
	id := filepath.Base(path)
	uuid, err := uuid.Parse(id)
	if err != nil {
		resp := &je.Response{
			Code:    "bad-request",
			Message: fmt.Sprintf("could not deserialize manifest: %v", err),
		}
		log.Warn().Err(err).Msg("could not deserialize manifest")
		je.Error(w, resp, http.StatusBadRequest)
		return
	}

	_, err = h.serv.DeleteUpdateOperations(ctx, uuid)
	if err != nil {
		resp := &je.Response{
			Code:    "internal server error",
			Message: fmt.Sprintf("could not get update operations: %v", err),
		}
		je.Error(w, resp, http.StatusInternalServerError)
	}
}
