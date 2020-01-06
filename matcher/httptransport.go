package matcher

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/quay/claircore"
	je "github.com/quay/claircore/pkg/jsonerr"
)

var _ http.Handler = (*HTTP)(nil)

const (
	// VulnerabilityReportAPIPath is the http path for accessing vulnerability_report
	VulnerabilityReportAPIPath = "/api/v1/vulnerability_report/"
)

type HTTP struct {
	*http.ServeMux
	serv Service
	r    Reporter
}

type Reporter interface {
	IndexReport(context.Context, string) (*claircore.IndexReport, bool, error)
}

func NewHTTPTransport(service Service, r Reporter) (*HTTP, error) {
	h := &HTTP{
		r:    r,
		serv: service,
	}
	mux := http.NewServeMux()
	h.Register(mux)
	h.ServeMux = mux
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
	ctx, done := context.WithCancel(r.Context())
	defer done()

	manifestHash := strings.TrimPrefix(r.URL.Path, VulnerabilityReportAPIPath)
	if manifestHash == "" {
		resp := &je.Response{
			Code:    "bad-request",
			Message: "malformed path. provide a single manifest hash",
		}
		je.Error(w, resp, http.StatusBadRequest)
		return
	}

	indexReport, ok, err := h.r.IndexReport(ctx, manifestHash)
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

	vulnReport, err := h.serv.Scan(ctx, indexReport)
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
