package httptransport

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path"
	"time"

	"github.com/quay/claircore"
	"github.com/quay/claircore/pkg/tarfs"
	"github.com/quay/zlog"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/quay/clair/v4/indexer"
	"github.com/quay/clair/v4/internal/codec"
	"github.com/quay/clair/v4/internal/httputil"
	"github.com/quay/clair/v4/middleware/compress"
)

// NewIndexerV1 returns an http.Handler serving the Indexer V1 API rooted at
// "prefix".
func NewIndexerV1(_ context.Context, prefix string, srv indexer.Service, topt otelhttp.Option) (*IndexerV1, error) {
	prefix = path.Join("/", prefix) // Ensure the prefix is rooted and cleaned.
	m := http.NewServeMux()
	h := IndexerV1{
		inner: otelhttp.NewHandler(
			compress.Handler(m),
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
	r = withRequestID(r)
	ctx := r.Context()
	var status int
	var length int64
	w = httputil.ResponseRecorder(&status, &length, w)
	defer func() {
		switch err := http.NewResponseController(w).Flush(); {
		case errors.Is(err, nil):
		case errors.Is(err, http.ErrNotSupported): // Skip
		default:
			zlog.Warn(ctx).
				Err(err).
				Msg("unable to flush http response")
		}
		zlog.Info(ctx).
			Str("remote_addr", r.RemoteAddr).
			Str("method", r.Method).
			Str("request_uri", r.RequestURI).
			Int("status", status).
			Int64("written", length).
			Dur("duration", time.Since(start)).
			Msg("handled HTTP request")
	}()
	h.inner.ServeHTTP(w, r)
}

func (h *IndexerV1) indexReport(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	switch r.Method {
	case http.MethodPost:
	case http.MethodDelete:
	default:
		apiError(ctx, w, http.StatusMethodNotAllowed, "method disallowed: %s", r.Method)
	}
	defer r.Body.Close()
	dec := codec.GetDecoder(r.Body)
	defer codec.PutDecoder(dec)
	switch r.Method {
	case http.MethodPost:
		state, err := h.srv.State(ctx)
		if err != nil {
			apiError(ctx, w, http.StatusInternalServerError, "could not retrieve indexer state: %v", err)
		}
		var m claircore.Manifest
		if err := dec.Decode(&m); err != nil {
			apiError(ctx, w, http.StatusBadRequest, "failed to deserialize manifest: %v", err)
		}
		if m.Hash.String() == "" || len(m.Layers) == 0 {
			apiError(ctx, w, http.StatusBadRequest, "bogus manifest")
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
		switch {
		case errors.Is(err, nil):
		case errors.Is(err, tarfs.ErrFormat):
			apiError(ctx, w, http.StatusBadRequest, "failed to start scan: %v", err)
		default:
			apiError(ctx, w, http.StatusInternalServerError, "failed to start scan: %v", err)
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
			apiError(ctx, w, http.StatusBadRequest, "failed to deserialize bulk delete: %v", err)
		}
		ds, err := h.srv.DeleteManifests(ctx, ds...)
		if err != nil {
			apiError(ctx, w, http.StatusInternalServerError, "could not delete manifests: %v", err)
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
	ctx := r.Context()
	switch r.Method {
	case http.MethodGet:
	case http.MethodDelete:
	default:
		apiError(ctx, w, http.StatusMethodNotAllowed, "method disallowed: %s", r.Method)
	}
	d, err := getDigest(w, r)
	if err != nil {
		apiError(ctx, w, http.StatusBadRequest, "malformed path: %v", err)
	}
	switch r.Method {
	case http.MethodGet:
		allow := []string{"application/vnd.clair.indexreport.v1+json", "application/json"}
		switch err := pickContentType(w, r, allow); {
		case errors.Is(err, nil): // OK
		case errors.Is(err, ErrMediaType):
			apiError(ctx, w, http.StatusUnsupportedMediaType, "unable to negotiate common media type for %v", allow)
		default:
			apiError(ctx, w, http.StatusBadRequest, "malformed request: %v", err)
		}

		state, err := h.srv.State(ctx)
		if err != nil {
			apiError(ctx, w, http.StatusInternalServerError, "could not retrieve indexer state: %v", err)
		}
		validator := `"` + state + `"`
		if unmodified(r, validator) {
			w.WriteHeader(http.StatusNotModified)
			return
		}

		report, ok, err := h.srv.IndexReport(ctx, d)
		if !ok {
			apiError(ctx, w, http.StatusNotFound, "index report not found")
		}
		if err != nil {
			apiError(ctx, w, http.StatusInternalServerError, "could not retrieve index report: %v", err)
		}

		w.Header().Add("etag", validator)
		defer writerError(w, &err)()
		enc := codec.GetEncoder(w)
		defer codec.PutEncoder(enc)
		err = enc.Encode(report)
	case http.MethodDelete:
		if _, err := h.srv.DeleteManifests(ctx, d); err != nil {
			apiError(ctx, w, http.StatusInternalServerError, "unable to delete manifest: %v", err)
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func (h *IndexerV1) indexState(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if r.Method != http.MethodGet {
		apiError(ctx, w, http.StatusMethodNotAllowed, "method disallowed: %s", r.Method)
	}
	allow := []string{"application/vnd.clair.indexstate.v1+json", "application/json"}
	switch err := pickContentType(w, r, allow); {
	case errors.Is(err, nil): // OK
	case errors.Is(err, ErrMediaType):
		apiError(ctx, w, http.StatusUnsupportedMediaType, "unable to negotiate common media type for %v", allow)
	default:
		apiError(ctx, w, http.StatusBadRequest, "malformed request: %v", err)
	}
	s, err := h.srv.State(ctx)
	if err != nil {
		apiError(ctx, w, http.StatusInternalServerError, "could not retrieve indexer state: %v", err)
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
	ctx := r.Context()
	if r.Method != http.MethodPost {
		apiError(ctx, w, http.StatusMethodNotAllowed, "method disallowed: %s", r.Method)
	}
	allow := []string{"application/vnd.clair.affectedmanifests.v1+json", "application/json"}
	switch err := pickContentType(w, r, allow); {
	case errors.Is(err, nil): // OK
	case errors.Is(err, ErrMediaType):
		apiError(ctx, w, http.StatusUnsupportedMediaType, "unable to negotiate common media type for %v", allow)
	default:
		apiError(ctx, w, http.StatusBadRequest, "malformed request: %v", err)
	}

	var vulnerabilities struct {
		V []claircore.Vulnerability `json:"vulnerabilities"`
	}
	dec := codec.GetDecoder(r.Body)
	defer codec.PutDecoder(dec)
	if err := dec.Decode(&vulnerabilities); err != nil {
		apiError(ctx, w, http.StatusBadRequest, "failed to deserialize vulnerabilities: %v", err)
	}

	affected, err := h.srv.AffectedManifests(ctx, vulnerabilities.V)
	if err != nil {
		apiError(ctx, w, http.StatusInternalServerError, "could not retrieve affected manifests: %v", err)
	}

	defer writerError(w, &err)
	enc := codec.GetEncoder(w)
	defer codec.PutEncoder(enc)
	err = enc.Encode(affected)
}

func init() {
	indexerv1wrapper.init("indexerv1")
}

var indexerv1wrapper wrapper
