package indexer

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"sort"
	"strings"

	"github.com/quay/claircore"
	je "github.com/quay/claircore/pkg/jsonerr"
)

var _ http.Handler = (*HTTP)(nil)

const (
	IndexAPIPath       = "/api/v1/index_report"
	IndexReportAPIPath = "/api/v1/index_report/"
	StateAPIPath       = "/api/v1/state"
)

type HTTP struct {
	*http.ServeMux
	serv Service
}

func NewHTTPTransport(service Service) (*HTTP, error) {
	h := &HTTP{
		serv: service,
	}
	mux := http.NewServeMux()
	h.Register(mux)
	h.ServeMux = mux
	return h, nil
}

func (h *HTTP) IndexReportHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if r.Method != http.MethodGet {
		resp := &je.Response{
			Code:    "method-not-allowed",
			Message: "endpoint only allows GET",
		}
		je.Error(w, resp, http.StatusMethodNotAllowed)
		return
	}

	manifestStr := strings.TrimPrefix(r.URL.Path, IndexReportAPIPath)
	if manifestStr == "" {
		resp := &je.Response{
			Code:    "bad-request",
			Message: "malformed path. provide a single manifest hash",
		}
		je.Error(w, resp, http.StatusBadRequest)
		return
	}
	manifest, err := claircore.ParseDigest(manifestStr)
	if err != nil {
		resp := &je.Response{
			Code:    "bad-request",
			Message: "malformed path: " + err.Error(),
		}
		je.Error(w, resp, http.StatusBadRequest)
		return
	}

	report, ok, err := h.serv.IndexReport(ctx, manifest)
	if !ok {
		resp := &je.Response{
			Code:    "not-found",
			Message: fmt.Sprintf("index report for manifest %q not found", manifest.String()),
		}
		je.Error(w, resp, http.StatusNotFound)
		return
	}
	if err != nil {
		resp := &je.Response{
			Code:    "internal-server-error",
			Message: err.Error(),
		}
		je.Error(w, resp, http.StatusInternalServerError)
		return
	}

	err = json.NewEncoder(w).Encode(report)
	if err != nil {
		resp := &je.Response{
			Code:    "encoding-error",
			Message: fmt.Sprintf("failed to encode scan report: %v", err),
		}
		je.Error(w, resp, http.StatusInternalServerError)
		return
	}
}

func (h *HTTP) IndexHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		resp := &je.Response{
			Code:    "method-not-allowed",
			Message: "endpoint only allows POST",
		}
		je.Error(w, resp, http.StatusMethodNotAllowed)
		return
	}

	var m claircore.Manifest
	err := json.NewDecoder(r.Body).Decode(&m)
	if err != nil {
		resp := &je.Response{
			Code:    "bad-request",
			Message: fmt.Sprintf("failed to deserialize manifest: %v", err),
		}
		je.Error(w, resp, http.StatusBadRequest)
		return
	}

	// TODO Validate manifest structure.

	// TODO Do we need some sort of background context embedded in the HTTP
	// struct?
	report, err := h.serv.Index(context.TODO(), &m)
	if err != nil {
		resp := &je.Response{
			Code:    "index-error",
			Message: fmt.Sprintf("failed to start scan: %v", err),
		}
		je.Error(w, resp, http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	w.Header().Set("location", path.Join(IndexReportAPIPath, m.Hash.String()))
	err = json.NewEncoder(w).Encode(report)
	if err != nil {
		resp := &je.Response{
			Code:    "encoding-error",
			Message: fmt.Sprintf("failed to encode scan report: %v", err),
		}
		je.Error(w, resp, http.StatusInternalServerError)
		return
	}
}

func (h *HTTP) StateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	s := h.serv.State()
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

// Register will register the api on a given mux.
func (h *HTTP) Register(mux *http.ServeMux) {
	mux.HandleFunc(IndexAPIPath, h.IndexHandler)
	mux.HandleFunc(IndexReportAPIPath, h.IndexReportHandler)
	mux.HandleFunc(StateAPIPath, h.StateHandler)
}
