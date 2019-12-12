package indexer

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/quay/claircore"
	je "github.com/quay/claircore/pkg/jsonerr"
)

var _ http.Handler = &HTTP{}

const (
	IndexAPIPath       = "/api/v1/index"
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
	if r.Method != http.MethodGet {
		resp := &je.Response{
			Code:    "method-not-allowed",
			Message: "endpoint only allows GET",
		}
		je.Error(w, resp, http.StatusMethodNotAllowed)
		return
	}

	manifestHash := strings.TrimPrefix(r.URL.Path, IndexReportAPIPath)
	if manifestHash == "" {
		resp := &je.Response{
			Code:    "bad-request",
			Message: "malformed path. provide a single manifest hash",
		}
		je.Error(w, resp, http.StatusBadRequest)
		return
	}

	report, ok, err := h.serv.IndexReport(context.Background(), manifestHash)
	if !ok {
		resp := &je.Response{
			Code:    "not-found",
			Message: fmt.Sprintf("index report for manifest %s not found", manifestHash),
		}
		je.Error(w, resp, http.StatusNotFound)
		return
	}
	if err != nil {
		resp := &je.Response{
			Code:    "internal-server-error",
			Message: fmt.Sprintf("%w", err),
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

	// ToDo: manifest structure validation
	report, err := h.serv.Index(context.Background(), &m)
	if err != nil {
		resp := &je.Response{
			Code:    "index-error",
			Message: fmt.Sprintf("failed to start scan: %v", err),
		}
		je.Error(w, resp, http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
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
	w.Header().Set("content-type", "text/plain")
	// No trailing newline, so a client can't get confused about whether it
	// counts or not.
	fmt.Fprint(w, s)
}

// Register will register the api on a given mux.
func (h *HTTP) Register(mux *http.ServeMux) {
	mux.HandleFunc(IndexAPIPath, h.IndexHandler)
	mux.HandleFunc(IndexReportAPIPath, h.IndexReportHandler)
	mux.HandleFunc(StateAPIPath, h.StateHandler)
}
