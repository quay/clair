package matcher

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptrace"
	"strings"
	"time"

	"github.com/quay/claircore"
	je "github.com/quay/claircore/pkg/jsonerr"
	"go.opentelemetry.io/otel/api/global"
	"go.opentelemetry.io/otel/api/key"
	"go.opentelemetry.io/otel/api/metric"
	"go.opentelemetry.io/otel/api/unit"
	oteltrace "go.opentelemetry.io/otel/plugin/httptrace"
	"go.opentelemetry.io/otel/plugin/othttp"

	"github.com/quay/clair/v4/indexer"
)

var _ http.Handler = (*HTTP)(nil)

const (
	v1Root = "/api/v1/"
	// VulnerabilityReportAPIPath is the http path for accessing vulnerability_report
	VulnerabilityReportAPIPath = v1Root + "vulnerability_report/"
)

type HTTP struct {
	*http.ServeMux
	serv Service
	r    indexer.Reporter

	meter   metric.Meter
	latency *metric.Int64Measure
}

var pathKey = key.New("http.path")

func NewHTTPTransport(service Service, r indexer.Reporter) (*HTTP, error) {
	meter := global.MeterProvider().Meter("projectquay.io/clair")
	late := meter.NewInt64Measure("projectquay.io.clair.matcher.latency",
		metric.WithDescription("Latency of matcher requests."),
		metric.WithUnit(unit.Milliseconds),
		metric.WithAbsolute(true),
		metric.WithKeys(pathKey),
	)
	h := &HTTP{
		r:       r,
		serv:    service,
		meter:   meter,
		latency: &late,
	}
	mux := http.NewServeMux()
	h.Register(mux)
	h.ServeMux = mux
	return h, nil
}

func (h *HTTP) VulnerabilityReportHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	start := time.Now()
	labels := h.meter.Labels(pathKey.String(VulnerabilityReportAPIPath))
	defer func() {
		h.latency.Record(ctx, time.Now().Sub(start).Milliseconds(), labels)
	}()
	w.Header().Set("content-type", "application/json")
	if r.Method != http.MethodGet {
		resp := &je.Response{
			Code:    "method-not-allowed",
			Message: "endpoint only allows GET",
		}
		je.Error(w, resp, http.StatusMethodNotAllowed)
		return
	}
	ctx, done := context.WithCancel(ctx)
	defer done()
	ctx = httptrace.WithClientTrace(ctx, oteltrace.NewClientTrace(ctx))

	manifestStr := strings.TrimPrefix(r.URL.Path, VulnerabilityReportAPIPath)
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

	indexReport, ok, err := h.r.IndexReport(ctx, manifest)
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

	w.WriteHeader(http.StatusOK)
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
	hf := http.HandlerFunc(h.VulnerabilityReportHandler)
	tr := othttp.WithTracer(global.TraceProvider().Tracer("clair"))
	nh := othttp.NewHandler(hf, "matcher/VulnerabilityReport", tr)
	mux.Handle(VulnerabilityReportAPIPath, othttp.WithRouteTag(VulnerabilityReportAPIPath+":manifest", nh))
}
