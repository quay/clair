package httptransport

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path"

	"github.com/google/uuid"
	"github.com/quay/claircore/pkg/jsonerr"

	"github.com/quay/clair/v4/matcher"
)

type updateDiffHandler struct {
	matcher.Differ
}

func (h *updateDiffHandler) getLatest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	ctx := r.Context()
	var validator string
	if latest, err := h.Differ.LatestUpdateOperation(ctx); err == nil {
		// Using a validator is an optimization.
		validator = `"` + latest.String() + `"`
		if unmodified(r, validator) {
			w.WriteHeader(http.StatusNotModified)
			return
		}
	}

	m, err := h.LatestUpdateOperations(ctx)
	if err != nil {
		res := &jsonerr.Response{
			Code:    "update-error",
			Message: fmt.Sprintf("failed to get latest update operations: %v", err),
		}
		jsonerr.Error(w, res, http.StatusInternalServerError)
		return
	}
	if validator != "" {
		w.Header().Set("etag", validator)
	}
	defer writerError(w, &err)()
	err = json.NewEncoder(w).Encode(m)
}

func (h *updateDiffHandler) deleteRef(w http.ResponseWriter, r *http.Request, ref uuid.UUID) {
	if r.Method != http.MethodDelete {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	ctx := r.Context()
	if err := h.DeleteUpdateOperations(ctx, ref); err != nil {
		res := &jsonerr.Response{
			Code:    "update-error",
			Message: fmt.Sprintf("failed to delete diff: %v", err),
		}
		jsonerr.Error(w, res, http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *updateDiffHandler) getUpdates(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	ctx := r.Context()
	var prev, cur uuid.UUID
	var err error
	q := r.URL.Query()
	prevQ, curQ := q.Get("prev"), q.Get("cur")

	cur, err = uuid.Parse(curQ)
	if err != nil {
		res := &jsonerr.Response{
			Code:    "update-error",
			Message: fmt.Sprintf("malformed ref: %q", curQ),
		}
		jsonerr.Error(w, res, http.StatusBadRequest)
		return
	}
	if prevQ == "" {
		prev = uuid.Nil
	} else {
		prev, err = uuid.Parse(prevQ)
		if err != nil {
			res := &jsonerr.Response{
				Code:    "update-error",
				Message: fmt.Sprintf("malformed ref: %q", prevQ),
			}
			jsonerr.Error(w, res, http.StatusBadRequest)
			return
		}
	}
	u, err := h.UpdateDiff(ctx, prev, cur)
	if err != nil {
		res := &jsonerr.Response{
			Code:    "update-error",
			Message: fmt.Sprintf("failed to get diff: %v", err),
		}
		jsonerr.Error(w, res, http.StatusInternalServerError)
		return
	}
	defer writerError(w, &err)()
	err = json.NewEncoder(w).Encode(u)
}

func UpdateDiffHandler(d matcher.Differ) (http.Handler, error) {
	h := &updateDiffHandler{d}
	mux := http.NewServeMux()
	mux.HandleFunc(path.Clean(UpdatesAPIPath), http.HandlerFunc(h.getLatest))
	mux.HandleFunc(UpdatesAPIPath, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == UpdatesAPIPath {
			h.getLatest(w, r)
			return
		}
		ref, err := uuid.Parse(path.Base(r.URL.Path))
		if err == nil {
			h.deleteRef(w, r, ref)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	mux.HandleFunc(path.Join(UpdatesAPIPath, "diff"), http.HandlerFunc(h.getUpdates))
	return mux, nil
}
