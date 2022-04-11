package httptransport

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path"
	"time"

	"github.com/ldelossa/responserecorder"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/quay/claircore"
	"github.com/quay/zlog"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/quay/clair/v4/indexer"
	"github.com/quay/clair/v4/internal/codec"
)

// NewIndexerV1 returns an http.Handler serving the Indexer V1 API rooted at
// "prefix".
func NewIndexerV1(_ context.Context, prefix string, srv indexer.Service, topt otelhttp.Option) (*IndexerV1, error) {
	prefix = path.Join("/", prefix) // Ensure the prefix is rooted and cleaned.
	m := http.NewServeMux()
	h := IndexerV1{
		inner: otelhttp.NewHandler(
			m,
			"indexerv1",
			otelhttp.WithMessageEvents(otelhttp.ReadEvents, otelhttp.WriteEvents),
			topt,
		),
		srv: srv,
	}
	p := path.Join(prefix, "index_report")
	m.Handle(p, indexerv1wrapper.wrapFunc(p, h.indexReport))
	p += "/"
	m.Handle(p, indexerv1wrapper.wrapFunc(path.Join(p, ":digest"), h.indexReportOne))
	p = path.Join(prefix, "index_state")
	m.Handle(p, indexerv1wrapper.wrapFunc(p, h.indexState))
	p = path.Join(prefix, "internal", "affected_manifest") + "/"
	m.Handle(p, indexerv1wrapper.wrapFunc(p, h.affectedManifests))

	return &h, nil
}

// IndexerV1 is a consolidated Indexer endpoint.
type IndexerV1 struct {
	inner http.Handler
	srv   indexer.Service
}

var _ http.Handler = (*IndexerV1)(nil)

// ServeHTTP implements http.Handler.
func (h *IndexerV1) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	ctx := zlog.ContextWithValues(r.Context(), "request_id", r.Header.Get("x-request-id"))
	r = r.WithContext(ctx)
	wr := responserecorder.NewResponseRecorder(w)
	defer func() {
		if f, ok := wr.(http.Flusher); ok {
			f.Flush()
		}
		zlog.Info(r.Context()).
			Str("remote_addr", r.RemoteAddr).
			Str("method", r.Method).
			Str("request_uri", r.RequestURI).
			Int("status", wr.StatusCode()).
			Dur("duration", time.Since(start)).
			Msg("handled HTTP request")
	}()
	h.inner.ServeHTTP(wr, r)
}

func (h *IndexerV1) indexReport(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
	case http.MethodDelete:
	default:
		apiError(w, http.StatusMethodNotAllowed, "method disallowed: %s", r.Method)
		return
	}
	ctx := r.Context()
	defer r.Body.Close()
	dec := codec.GetDecoder(r.Body)
	defer codec.PutDecoder(dec)
	switch r.Method {
	case http.MethodPost:
		state, err := h.srv.State(ctx)
		if err != nil {
			apiError(w, http.StatusInternalServerError, "could not retrieve indexer state: %v", err)
			return
		}
		var m claircore.Manifest
		if err := dec.Decode(&m); err != nil {
			apiError(w, http.StatusBadRequest, "failed to deserialize manifest: %v", err)
			return
		}
		if m.Hash.String() == "" || len(m.Layers) == 0 {
			apiError(w, http.StatusBadRequest, "bogus manifest")
			return
		}
		next := path.Join(r.URL.Path, m.Hash.String())

		w.Header().Add("link", fmt.Sprintf(linkIndex, next))
		w.Header().Add("link", fmt.Sprintf(linkReport, path.Join(VulnerabilityReportPath, m.Hash.String())))
		validator := `"` + state + `"`
		if unmodified(r, validator) {
			w.WriteHeader(http.StatusPreconditionFailed)
			return
		}

		// TODO Do we need some sort of background context embedded in the HTTP
		// struct?
		report, err := h.srv.Index(ctx, &m)
		if err != nil {
			apiError(w, http.StatusInternalServerError, "failed to start scan: %v", err)
			return
		}

		w.Header().Set("etag", validator)
		w.Header().Set("location", next)
		defer writerError(w, &err)()
		w.WriteHeader(http.StatusCreated)
		enc := codec.GetEncoder(w)
		defer codec.PutEncoder(enc)
		err = enc.Encode(report)
	case http.MethodDelete:
		var ds []claircore.Digest
		if err := dec.Decode(&ds); err != nil {
			apiError(w, http.StatusBadRequest, "failed to deserialize bulk delete: %v", err)
			return
		}
		ds, err := h.srv.DeleteManifests(ctx, ds...)
		if err != nil {
			apiError(w, http.StatusInternalServerError, "could not delete manifests: %v", err)
			return
		}
		zlog.Debug(ctx).
			Int("count", len(ds)).
			Msg("manifests deleted")
		defer writerError(w, &err)()
		w.WriteHeader(http.StatusOK)
		enc := codec.GetEncoder(w)
		defer codec.PutEncoder(enc)
		err = enc.Encode(ds)
	}
}

const (
	linkIndex  = `<%s>; rel="https://projectquay.io/clair/v1/index_report"`
	linkReport = `<%s>; rel="https://projectquay.io/clair/v1/vulnerability_report"`
)

func (h *IndexerV1) indexReportOne(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
	case http.MethodDelete:
	default:
		apiError(w, http.StatusMethodNotAllowed, "method disallowed: %s", r.Method)
		return
	}
	d, err := getDigest(w, r)
	if err != nil {
		apiError(w, http.StatusBadRequest, "malformed path: %v", err)
		return
	}
	ctx := r.Context()
	switch r.Method {
	case http.MethodGet:
		allow := []string{"application/vnd.clair.indexreport.v1+json", "application/json"}
		switch err := pickContentType(w, r, allow); {
		case errors.Is(err, nil): // OK
		case errors.Is(err, ErrMediaType):
			apiError(w, http.StatusUnsupportedMediaType, "unable to negotiate common media type for %v", allow)
			return
		default:
			apiError(w, http.StatusBadRequest, "malformed request: %v", err)
			return
		}

		state, err := h.srv.State(ctx)
		if err != nil {
			apiError(w, http.StatusInternalServerError, "could not retrieve indexer state: %v", err)
			return
		}
		validator := `"` + state + `"`
		if unmodified(r, validator) {
			w.WriteHeader(http.StatusNotModified)
			return
		}

		report, ok, err := h.srv.IndexReport(ctx, d)
		if !ok {
			apiError(w, http.StatusNotFound, "index report not found")
			return
		}
		if err != nil {
			apiError(w, http.StatusInternalServerError, "could not retrieve index report: %v", err)
			return
		}

		w.Header().Add("etag", validator)
		defer writerError(w, &err)()
		enc := codec.GetEncoder(w)
		defer codec.PutEncoder(enc)
		err = enc.Encode(report)
	case http.MethodDelete:
		if _, err := h.srv.DeleteManifests(ctx, d); err != nil {
			apiError(w, http.StatusInternalServerError, "unable to delete manifest: %v", err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func (h *IndexerV1) indexState(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		apiError(w, http.StatusMethodNotAllowed, "method disallowed: %s", r.Method)
		return
	}
	allow := []string{"application/vnd.clair.indexstate.v1+json", "application/json"}
	switch err := pickContentType(w, r, allow); {
	case errors.Is(err, nil): // OK
	case errors.Is(err, ErrMediaType):
		apiError(w, http.StatusUnsupportedMediaType, "unable to negotiate common media type for %v", allow)
		return
	default:
		apiError(w, http.StatusBadRequest, "malformed request: %v", err)
		return
	}
	ctx := r.Context()
	s, err := h.srv.State(ctx)
	if err != nil {
		apiError(w, http.StatusInternalServerError, "could not retrieve indexer state: %v", err)
		return
	}

	tag := `"` + s + `"`
	w.Header().Add("etag", tag)

	if unmodified(r, tag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}

	defer writerError(w, &err)()
	// TODO(hank) Don't use an encoder to write out like 40 bytes of json.
	enc := codec.GetEncoder(w)
	defer codec.PutEncoder(enc)
	err = enc.Encode(struct {
		State string `json:"state"`
	}{
		State: s,
	})
}

func (h *IndexerV1) affectedManifests(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		apiError(w, http.StatusMethodNotAllowed, "method disallowed: %s", r.Method)
		return
	}
	allow := []string{"application/vnd.clair.affectedmanifests.v1+json", "application/json"}
	switch err := pickContentType(w, r, allow); {
	case errors.Is(err, nil): // OK
	case errors.Is(err, ErrMediaType):
		apiError(w, http.StatusUnsupportedMediaType, "unable to negotiate common media type for %v", allow)
		return
	default:
		apiError(w, http.StatusBadRequest, "malformed request: %v", err)
		return
	}
	ctx := r.Context()

	var vulnerabilities struct {
		V []claircore.Vulnerability `json:"vulnerabilities"`
	}
	dec := codec.GetDecoder(r.Body)
	defer codec.PutDecoder(dec)
	if err := dec.Decode(&vulnerabilities); err != nil {
		apiError(w, http.StatusBadRequest, "failed to deserialize vulnerabilities: %v", err)
		return
	}

	affected, err := h.srv.AffectedManifests(ctx, vulnerabilities.V)
	if err != nil {
		apiError(w, http.StatusInternalServerError, "could not retrieve affected manifests: %v", err)
		return
	}

	defer writerError(w, &err)
	enc := codec.GetEncoder(w)
	defer codec.PutEncoder(enc)
	err = enc.Encode(affected)
}

func init() {
	indexerv1wrapper.init()
}

var indexerv1wrapper = &wrapper{
	RequestCount: prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricNamespace,
			Subsystem: metricSubsystem,
			Name:      "indexerv1_request_total",
			Help:      "A total count of http requests for the given path",
		},
		[]string{"handler", "code", "method"},
	),
	RequestSize: prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: metricNamespace,
			Subsystem: metricSubsystem,
			Name:      "indexerv1_request_size_bytes",
			Help:      "Distribution of request sizes for the given path",
		},
		[]string{"handler", "code", "method"},
	),
	ResponseSize: prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: metricNamespace,
			Subsystem: metricSubsystem,
			Name:      "indexerv1_response_size_bytes",
			Help:      "Distribution of response sizes for the given path",
		}, []string{"handler", "code", "method"},
	),
	RequestDuration: prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: metricNamespace,
			Subsystem: metricSubsystem,
			Name:      "indexerv1_request_duration_seconds",
			Help:      "Distribution of request durations for the given path",
			Buckets:   prometheus.ExponentialBucketsRange(1, 300, 15),
		}, []string{"handler", "code", "method"},
	),
	InFlight: prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: metricNamespace,
			Subsystem: metricSubsystem,
			Name:      "indexerv1_in_flight_requests",
			Help:      "Gauge of requests in flight",
		},
		[]string{"handler"},
	),
}
