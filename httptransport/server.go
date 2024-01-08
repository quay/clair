// Package httptransport contains the HTTP logic for implementing the Clair(v4)
// HTTP API v1.
package httptransport

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/quay/clair/config"
	"github.com/quay/zlog"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"golang.org/x/sync/semaphore"

	"github.com/quay/clair/v4/indexer"
	"github.com/quay/clair/v4/matcher"
	"github.com/quay/clair/v4/notifier"
)

// These are the various endpoints of the v1 API.
const (
	apiRoot                      = "/api/v1/"
	indexerRoot                  = "/indexer"
	matcherRoot                  = "/matcher"
	notifierRoot                 = "/notifier"
	internalRoot                 = apiRoot + "internal/"
	IndexAPIPath                 = indexerRoot + apiRoot + "index_report"
	IndexReportAPIPath           = indexerRoot + apiRoot + "index_report/"
	IndexStateAPIPath            = indexerRoot + apiRoot + "index_state"
	AffectedManifestAPIPath      = indexerRoot + internalRoot + "affected_manifest/"
	VulnerabilityReportPath      = matcherRoot + apiRoot + "vulnerability_report/"
	UpdateOperationAPIPath       = matcherRoot + internalRoot + "update_operation"
	UpdateOperationDeleteAPIPath = matcherRoot + internalRoot + "update_operation/"
	UpdateDiffAPIPath            = matcherRoot + internalRoot + "update_diff"
	NotificationAPIPath          = notifierRoot + apiRoot + "notification/"
	KeysAPIPath                  = notifierRoot + apiRoot + "services/notifier/keys"
	KeyByIDAPIPath               = notifierRoot + apiRoot + "services/notifier/keys/"
	OpenAPIV1Path                = "/openapi/v1"
)

// New configures an http.Handler serving the v1 API or a portion of it,
// according to the passed Config object.
func New(ctx context.Context, conf *config.Config, indexer indexer.Service, matcher matcher.Service, notifier notifier.Service) (http.Handler, error) {
	mux := http.NewServeMux()
	traceOpt := otelhttp.WithTracerProvider(otel.GetTracerProvider())
	ctx = zlog.ContextWithValues(ctx, "component", "httptransport/New")

	mux.Handle(OpenAPIV1Path, DiscoveryHandler(ctx, OpenAPIV1Path, traceOpt))
	zlog.Info(ctx).Str("path", OpenAPIV1Path).Msg("openapi discovery configured")

	// NOTE(hank) My brain always wants to rewrite constructions like the
	// following as a switch, but this is actually cleaner as an "if" sequence.

	if conf.Mode == config.IndexerMode || conf.Mode == config.ComboMode {
		if indexer == nil {
			return nil, fmt.Errorf("mode %q requires an indexer service", conf.Mode)
		}
		prefix := indexerRoot + apiRoot

		v1, err := NewIndexerV1(ctx, prefix, indexer, traceOpt)
		if err != nil {
			return nil, fmt.Errorf("indexer configuration: %w", err)
		}
		var sem *semaphore.Weighted
		if ct := conf.Indexer.IndexReportRequestConcurrency; ct > 0 {
			sem = semaphore.NewWeighted(int64(ct))
		}
		rl := &limitHandler{
			Check: func(r *http.Request) (*semaphore.Weighted, string) {
				if r.Method != http.MethodPost && r.URL.Path != IndexAPIPath {
					return nil, ""
				}
				// Nil if the relevant config option isn't set.
				return sem, IndexAPIPath
			},
			Next: v1,
		}
		mux.Handle(prefix, rl)
	}
	if conf.Mode == config.MatcherMode || conf.Mode == config.ComboMode {
		if indexer == nil || matcher == nil {
			return nil, fmt.Errorf("mode %q requires both an indexer service and a matcher service", conf.Mode)
		}
		prefix := matcherRoot + apiRoot
		v1 := NewMatcherV1(ctx, prefix, matcher, indexer, time.Duration(conf.Matcher.CacheAge), traceOpt)
		mux.Handle(prefix, v1)
	}
	if conf.Mode == config.NotifierMode || (conf.Mode == config.ComboMode && notifier != nil) {
		if notifier == nil {
			return nil, fmt.Errorf("mode %q requires a notifier service", conf.Mode)
		}
		prefix := notifierRoot + apiRoot
		v1, err := NewNotificationV1(ctx, prefix, notifier, traceOpt)
		if err != nil {
			return nil, fmt.Errorf("notifier configuration: %w", err)
		}
		mux.Handle(prefix, v1)
	}
	if conf.Mode == config.ComboMode && notifier == nil {
		zlog.Debug(ctx).Msg("skipping unconfigured notifier")
	}
	// Add endpoint authentication if configured to add auth. Must happen after
	// mux was configured for given mode.
	if conf.Auth.Any() {
		h, err := authHandler(conf, mux)
		if err != nil {
			zlog.Warn(ctx).
				Err(err).
				Msg("received error configuring auth middleware")
			return nil, err
		}
		final := http.NewServeMux()
		final.Handle("/robots.txt", robotsHandler)
		final.Handle("/", h)
		return final, nil
	}
	mux.Handle("/robots.txt", robotsHandler)
	return mux, nil
}

// IntraserviceIssuer is the issuer that will be used if Clair is configured to
// mint its own JWTs.
const IntraserviceIssuer = `clair-intraservice`

// Unmodified determines whether to return a conditional response.
func unmodified(r *http.Request, v string) bool {
	if vs, ok := r.Header["If-None-Match"]; ok {
		for _, rv := range vs {
			if rv == v {
				return true
			}
		}
	}
	return false
}

// WriterError is a helper that closes over an error that may be returned after
// writing a response body starts.
//
// The normal error flow can't be used, because the HTTP status code will have
// been sent and some amount of body data may have been written.
//
// To use this, make sure an error variable is predeclared and the returned
// function is deferred:
//
//	var err error
//	defer writerError(w, &err)()
//	_, err = fallibleWrite(w)
func writerError(w http.ResponseWriter, e *error) func() {
	const errHeader = `Clair-Error`
	w.Header().Add("trailer", errHeader)
	return func() {
		if *e == nil {
			return
		}
		w.Header().Add(errHeader, (*e).Error())
	}
}

// SetCacheControl sets the "Cache-Control" header on the response.
func setCacheControl(w http.ResponseWriter, age time.Duration) {
	// The odd format string means "print float as wide as needed and to 0
	// precision."
	const f = `max-age=%.f`
	w.Header().Set("cache-control", fmt.Sprintf(f, age.Seconds()))
}
