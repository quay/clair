package indexer

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/quay/claircore"
	je "github.com/quay/claircore/pkg/jsonerr"
	"go.opentelemetry.io/otel/api/global"
	"go.opentelemetry.io/otel/api/key"
	"go.opentelemetry.io/otel/api/metric"
	"go.opentelemetry.io/otel/api/unit"
	"go.opentelemetry.io/otel/plugin/othttp"
)

var _ http.Handler = (*HTTP)(nil)

const (
	v1Root             = "/api/v1/"
	IndexAPIPath       = v1Root + "index_report"
	IndexReportAPIPath = v1Root + "index_report/"
	StateAPIPath       = v1Root + "state"
)

type HTTP struct {
	*http.ServeMux
	serv Service

	meter   metric.Meter
	latency *metric.Int64Measure
}

var pathKey = key.New("http.path")

func NewHTTPTransport(service Service) (*HTTP, error) {
	meter := global.MeterProvider().Meter("projectquay.io/clair")
	late := meter.NewInt64Measure("projectquay.io.clair.indexer.latency",
		metric.WithDescription("Latency of indexer requests."),
		metric.WithUnit(unit.Milliseconds),
		metric.WithAbsolute(true),
		metric.WithKeys(pathKey),
	)
	h := &HTTP{
		serv:    service,
		meter:   meter,
		latency: &late,
	}
	mux := http.NewServeMux()
	h.Register(mux)
	h.ServeMux = mux
	return h, nil
}

func unmodified(r *http.Request, v string) bool {
	if vs, ok := r.Header["If-None-Match"]; ok {
		sort.Strings(vs)
		return sort.SearchStrings(vs, v) != -1
	}
	return false
}

func (h *HTTP) IndexReportHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	start := time.Now()
	labels := h.meter.Labels(pathKey.String(IndexReportAPIPath))
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

	state, err := h.serv.State(ctx)
	if err != nil {
		resp := &je.Response{
			Code:    "internal error",
			Message: "could not retrieve indexer state " + err.Error(),
		}
		je.Error(w, resp, http.StatusInternalServerError)
		return
	}
	validator := fmt.Sprintf(`"%s|%s"`, state, manifest.String())
	if unmodified(r, validator) {
		w.WriteHeader(http.StatusNotModified)
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

	w.Header().Add("etag", validator)
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

const (
	linkIndex  = `<%s>; rel="https://projectquay.io/clair/v1/index_report"`
	linkReport = `<%s>; rel="https://projectquay.io/clair/v1/vulnerability_report"`
)

func (h *HTTP) IndexHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	start := time.Now()
	labels := h.meter.Labels(pathKey.String(IndexAPIPath))
	defer func() {
		h.latency.Record(ctx, time.Now().Sub(start).Milliseconds(), labels)
	}()
	w.Header().Set("content-type", "application/json")
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
	report, err := h.serv.Index(ctx, &m)
	if err != nil {
		resp := &je.Response{
			Code:    "index-error",
			Message: fmt.Sprintf("failed to start scan: %v", err),
		}
		je.Error(w, resp, http.StatusInternalServerError)
		return
	}

	next := path.Join(IndexReportAPIPath, m.Hash.String())
	w.Header().Add("link", fmt.Sprintf(linkReport, path.Join(v1Root, "vulnerabilty_report", m.Hash.String())))
	w.Header().Add("link", fmt.Sprintf(linkIndex, next))
	w.Header().Set("location", next)
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(report); err != nil {
		w.Header().Set("clair-error", err.Error())
	}
}

func (h *HTTP) StateHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	start := time.Now()
	labels := h.meter.Labels(pathKey.String(StateAPIPath))
	defer func() {
		h.latency.Record(ctx, time.Now().Sub(start).Milliseconds(), labels)
	}()
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("content-type", "application/json")
	s, err := h.serv.State(ctx)
	if err != nil {
		resp := &je.Response{
			Code:    "internal error",
			Message: "could not retrieve indexer state " + err.Error(),
		}
		je.Error(w, resp, http.StatusInternalServerError)
		return
	}
	tag := `"` + s + `"`
	w.Header().Add("etag", tag)

	if unmodified(r, tag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	err = json.NewEncoder(w).Encode(stateSuccess{s})
	if err != nil {
		w.Header().Set("clair-error", err.Error())
	}
}

type stateSuccess struct {
	State string `json:"state"`
}

// Register will register the api on a given mux.
func (h *HTTP) Register(mux *http.ServeMux) {
	tr := othttp.WithTracer(global.TraceProvider().Tracer("clair"))
	for _, spec := range []struct {
		Path      string
		Tag       string
		Operation string
		Handler   http.Handler
	}{
		{
			Path:      IndexAPIPath,
			Tag:       IndexAPIPath,
			Operation: "indexer/Index",
			Handler:   http.HandlerFunc(h.IndexHandler),
		},
		{
			Path:      IndexReportAPIPath,
			Tag:       IndexReportAPIPath + ":manifest",
			Operation: "indexer/IndexReport",
			Handler:   http.HandlerFunc(h.IndexReportHandler),
		},
		{
			Path:      StateAPIPath,
			Tag:       StateAPIPath,
			Operation: "indexer/State",
			Handler:   http.HandlerFunc(h.StateHandler),
		},
	} {
		nh := othttp.NewHandler(spec.Handler, spec.Operation, tr)
		mux.Handle(spec.Path, othttp.WithRouteTag(spec.Tag, nh))
	}
}
