package httptransport

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptrace"
	"path"
	"path/filepath"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/quay/claircore"
	indexerController "github.com/quay/claircore/indexer/controller"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/zlog"
	oteltrace "go.opentelemetry.io/contrib/instrumentation/net/http/httptrace/otelhttptrace"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/quay/clair/v4/indexer"
	"github.com/quay/clair/v4/internal/codec"
	"github.com/quay/clair/v4/internal/httputil"
	"github.com/quay/clair/v4/matcher"
	"github.com/quay/clair/v4/middleware/compress"
)

// NewMatcherV1 returns an http.Handler serving the Matcher V1 API rooted at
// "prefix".
func NewMatcherV1(_ context.Context, prefix string, srv matcher.Service, indexerSrv indexer.Service, cacheAge time.Duration, topt otelhttp.Option) *MatcherV1 {
	prefix = path.Join("/", prefix) // Ensure the prefix is rooted and cleaned.
	m := http.NewServeMux()
	h := MatcherV1{
		inner: otelhttp.NewHandler(
			compress.Handler(m),
			"matcherv1",
			otelhttp.WithMessageEvents(otelhttp.ReadEvents, otelhttp.WriteEvents),
			topt,
		),
		srv:        srv,
		indexerSrv: indexerSrv,
		Cache:      cacheAge,
	}
	p := path.Join(prefix, "vulnerability_report") + "/"
	m.Handle(p, matcherv1wrapper.wrapFunc(p, h.vulnerabilityReport))
	p = path.Join(prefix, "internal", "update_operation")
	m.Handle(p, matcherv1wrapper.wrapFunc(p, h.updateOperationHandlerGet))
	p = path.Join(prefix, "internal", "update_operation") + "/"
	m.Handle(p, matcherv1wrapper.wrapFunc(p, h.updateOperationHandlerDelete))
	p = path.Join(prefix, "internal", "update_diff")
	m.Handle(p, matcherv1wrapper.wrapFunc(p, h.updateDiffHandler))

	return &h
}

// MatcherV1 is a consolidated Matcher endpoint.
type MatcherV1 struct {
	inner      http.Handler
	srv        matcher.Service
	indexerSrv indexer.Service
	Cache      time.Duration
}

var _ http.Handler = (*MatcherV1)(nil)

// ServeHTTP implements http.Handler.
func (h *MatcherV1) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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

func (h *MatcherV1) vulnerabilityReport(w http.ResponseWriter, r *http.Request) {
	ctx := zlog.ContextWithValues(r.Context(),
		"component", "httptransport/MatcherV1.vulnerabilityReport")

	if r.Method != http.MethodGet {
		apiError(ctx, w, http.StatusMethodNotAllowed, "endpoint only allows GET")
	}
	ctx, done := context.WithCancel(ctx)
	defer done()
	ctx = httptrace.WithClientTrace(ctx, oteltrace.NewClientTrace(ctx))

	manifestStr := path.Base(r.URL.Path)
	if manifestStr == "" {
		apiError(ctx, w, http.StatusBadRequest, "malformed path. provide a single manifest hash")
	}
	manifest, err := claircore.ParseDigest(manifestStr)
	if err != nil {
		apiError(ctx, w, http.StatusBadRequest, "malformed path: %v", err)
	}

	initd, err := h.srv.Initialized(ctx)
	if err != nil {
		apiError(ctx, w, http.StatusInternalServerError, err.Error())
	}
	if !initd {
		w.WriteHeader(http.StatusAccepted)
		return
	}

	indexReport, ok, err := h.indexerSrv.IndexReport(ctx, manifest)
	// check err first
	if err != nil {
		apiError(ctx, w, http.StatusInternalServerError, "experienced a server side error: %v", err)
	}
	// now check present and finished only after confirming no err
	if !ok || indexReport.State != indexerController.IndexFinished.String() {
		apiError(ctx, w, http.StatusNotFound, "index report for manifest %q not found", manifest.String())
		return
	}

	vulnReport, err := h.srv.Scan(ctx, indexReport)
	if err != nil {
		apiError(ctx, w, http.StatusInternalServerError, "failed to start scan: %v", err)
	}

	w.Header().Set("content-type", "application/json")
	setCacheControl(w, h.Cache)

	defer writerError(w, &err)()
	enc := codec.GetEncoder(w)
	defer codec.PutEncoder(enc)
	err = enc.Encode(vulnReport)
}

func (h *MatcherV1) updateDiffHandler(w http.ResponseWriter, r *http.Request) {
	ctx := zlog.ContextWithValues(r.Context(),
		"component", "httptransport/MatcherV1.updateDiffHandler")

	if r.Method != http.MethodGet {
		apiError(ctx, w, http.StatusMethodNotAllowed, "endpoint only allows GET")
	}
	// prev param is optional.
	var prev uuid.UUID
	var err error
	if param := r.URL.Query().Get("prev"); param != "" {
		prev, err = uuid.Parse(param)
		if err != nil {
			apiError(ctx, w, http.StatusBadRequest, "could not parse \"prev\" query param into uuid")
		}
	}

	// cur param is required
	var cur uuid.UUID
	var param string
	if param = r.URL.Query().Get("cur"); param == "" {
		apiError(ctx, w, http.StatusBadRequest, "\"cur\" query param is required")
	}
	if cur, err = uuid.Parse(param); err != nil {
		apiError(ctx, w, http.StatusBadRequest, "could not parse \"cur\" query param into uuid")
	}

	diff, err := h.srv.UpdateDiff(ctx, prev, cur)
	if err != nil {
		apiError(ctx, w, http.StatusInternalServerError, "could not get update operations: %v", err)
	}

	defer writerError(w, &err)()
	enc := codec.GetEncoder(w)
	defer codec.PutEncoder(enc)
	err = enc.Encode(&diff)
}

func (h *MatcherV1) updateOperationHandlerGet(w http.ResponseWriter, r *http.Request) {
	ctx := zlog.ContextWithValues(r.Context(),
		"component", "httptransport/MatcherV1.updateOperationHandlerGet")

	switch r.Method {
	case http.MethodGet:
	default:
		apiError(ctx, w, http.StatusMethodNotAllowed, "method disallowed: %s", r.Method)
	}

	kind := driver.VulnerabilityKind
	switch k := r.URL.Query().Get("kind"); k {
	case "enrichment":
		kind = driver.EnrichmentKind
	case "", "vulnerability":
		// Leave as default
	default:
		apiError(ctx, w, http.StatusBadRequest, "unknown kind: %q", k)
	}

	// handle conditional request. this is an optimization
	if ref, err := h.srv.LatestUpdateOperation(ctx, kind); err == nil {
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
		uos, err = h.srv.LatestUpdateOperations(ctx, kind)
	} else {
		uos, err = h.srv.UpdateOperations(ctx, kind)
	}
	if err != nil {
		apiError(ctx, w, http.StatusInternalServerError, "could not get update operations: %v", err)
	}

	defer writerError(w, &err)()
	enc := codec.GetEncoder(w)
	defer codec.PutEncoder(enc)
	err = enc.Encode(&uos)
}

func (h *MatcherV1) updateOperationHandlerDelete(w http.ResponseWriter, r *http.Request) {
	ctx := zlog.ContextWithValues(r.Context(),
		"component", "httptransport/MatcherV1.updateOperationHandlerDelete")
	switch r.Method {
	case http.MethodDelete:
	default:
		apiError(ctx, w, http.StatusMethodNotAllowed, "method disallowed: %s", r.Method)
	}

	path := r.URL.Path
	id := filepath.Base(path)
	uuid, err := uuid.Parse(id)
	if err != nil {
		zlog.Warn(ctx).Err(err).Msg("could not deserialize manifest")
		apiError(ctx, w, http.StatusBadRequest, "could not deserialize manifest: %v", err)
	}

	_, err = h.srv.DeleteUpdateOperations(ctx, uuid)
	if err != nil {
		apiError(ctx, w, http.StatusInternalServerError, "could not get update operations: %v", err)
	}
}

func init() {
	matcherv1wrapper.init("matcherv1")
}

var matcherv1wrapper wrapper
