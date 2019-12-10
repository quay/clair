package matcher

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/quay/clair/v4/indexer"
	je "github.com/quay/claircore/pkg/jsonerr"
)

var _ http.Handler = &HTTP{}

const (
	// VulnerabilityReportAPIPath is the http path for accessing vulnerability_report
	VulnerabilityReportAPIPath = "/api/v1/vulnerability_report/"
)

type HTTP struct {
	*http.ServeMux
	serv    Service
	indexer indexer.Service
}

func NewHTTPTransport(service Service, indexer indexer.Service) (*HTTP, error) {
	h := &HTTP{}
	mux := http.NewServeMux()
	mux.HandleFunc(VulnerabilityReportAPIPath, h.VulnerabilityReportHandler)
	h.ServeMux = mux
	h.serv = service
	h.indexer = indexer
	return h, nil
}

func (h *HTTP) VulnerabilityReportHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		resp := &je.Response{
			Code:    "method-not-allowed",
			Message: "endpoint only allows GET",
		}
		je.Error(w, resp, http.StatusMethodNotAllowed)
		return
	}

	manifestHash := strings.TrimPrefix(r.URL.Path, VulnerabilityReportAPIPath)
	if manifestHash == "" {
		resp := &je.Response{
			Code:    "bad-request",
			Message: "malformed path. provide a single manifest hash",
		}
		je.Error(w, resp, http.StatusBadRequest)
		return
	}

	indexReport, ok, err := h.indexer.IndexReport(context.Background(), manifestHash)
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
			Message: fmt.Sprintf("experienced a server side error: %v", err),
		}
		je.Error(w, resp, http.StatusInternalServerError)
		return
	}

	vulnReport, err := h.serv.Scan(context.Background(), indexReport)
	if err != nil {
		resp := &je.Response{
			Code:    "match-error",
			Message: fmt.Sprintf("failed to start scan: %v", err),
		}
		je.Error(w, resp, http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	err = json.NewEncoder(w).Encode(vulnReport)
	if err != nil {
		resp := &je.Response{
			Code:    "encoding-error",
			Message: fmt.Sprintf("failed to encode vulnerability report: %v", err),
		}
		je.Error(w, resp, http.StatusInternalServerError)
		return
	}
	return
}

func (h *HTTP) Register(mux *http.ServeMux) {
	mux.HandleFunc(VulnerabilityReportAPIPath, h.VulnerabilityReportHandler)
}
