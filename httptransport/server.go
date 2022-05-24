package httptransport

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/quay/clair/config"
	"github.com/quay/zlog"
	othttp "go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"golang.org/x/sync/semaphore"

	clairerror "github.com/quay/clair/v4/clair-error"
	"github.com/quay/clair/v4/indexer"
	"github.com/quay/clair/v4/matcher"
	intromw "github.com/quay/clair/v4/middleware/introspection"
	"github.com/quay/clair/v4/notifier"
)

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

// Server is the primary http server Clair exposes its functionality on.
type Server struct {
	// Server embeds a http.Server and http.ServeMux.
	// The http.Server will be configured with the ServeMux on successful
	// initialization.
	conf config.Config
	*http.Server
	*http.ServeMux
	indexer  indexer.Service
	matcher  matcher.Service
	notifier notifier.Service
	traceOpt othttp.Option
}

func New(ctx context.Context, conf config.Config, indexer indexer.Service, matcher matcher.Service, notifier notifier.Service) (*Server, error) {
	serv := &http.Server{
		Addr: conf.HTTPListenAddr,
		// use the passed in global context as the base context for all http
		// requests handled by this server
		BaseContext: func(net.Listener) context.Context { return ctx },
	}
	mux := http.NewServeMux()
	t := &Server{
		conf:     conf,
		Server:   serv,
		ServeMux: mux,
		indexer:  indexer,
		matcher:  matcher,
		notifier: notifier,
		traceOpt: othttp.WithTracerProvider(otel.GetTracerProvider()),
	}
	ctx = zlog.ContextWithValues(ctx, "component", "httptransport/New")

	if err := t.configureDiscovery(ctx); err != nil {
		zlog.Warn(ctx).Err(err).Msg("configuring openapi discovery failed")
	} else {
		zlog.Info(ctx).Str("path", OpenAPIV1Path).Msg("openapi discovery configured")
	}

	var e error
	switch conf.Mode {
	case config.ComboMode:
		e = t.configureComboMode(ctx)
		if e != nil {
			return nil, e
		}
	case config.IndexerMode:
		e = t.configureIndexerMode(ctx)
		if e != nil {
			return nil, e
		}
	case config.MatcherMode:
		e = t.configureMatcherMode(ctx)
		if e != nil {
			return nil, e
		}
	case config.NotifierMode:
		e = t.configureNotifierMode(ctx)
		if e != nil {
			return nil, e
		}
	}

	// attach HttpTransport to server, this works because we embed http.ServeMux
	t.Server.Handler = t

	// Add endpoint authentication if configured to add auth. Must happen after
	// mux was configured for given mode.
	if conf.Auth.Any() {
		err := t.configureWithAuth(ctx)
		if err != nil {
			zlog.Warn(ctx).
				Err(err).
				Msg("received error configuring auth middleware")
		}
	}

	return t, nil
}

// ConfigureDiscovery creates a discovery handler for serving the v1 OpenAPI
// specification.
func (t *Server) configureDiscovery(_ context.Context) error {
	t.Handle(OpenAPIV1Path,
		intromw.InstrumentedHandler(OpenAPIV1Path, t.traceOpt, DiscoveryHandler()))
	return nil
}

// ConfigureComboMode configures the HttpTransport for ComboMode.
//
// This mode runs both Indexer and Matcher in a single process.
func (t *Server) configureComboMode(ctx context.Context) error {
	// requires both indexer and matcher services
	if t.indexer == nil || t.matcher == nil {
		return clairerror.ErrNotInitialized{Msg: "Combo mode requires both indexer and macher services"}
	}

	err := t.configureIndexerMode(ctx)
	if err != nil {
		return clairerror.ErrNotInitialized{Msg: "could not configure indexer: " + err.Error()}
	}

	err = t.configureMatcherMode(ctx)
	if err != nil {
		return clairerror.ErrNotInitialized{Msg: "could not configure matcher: " + err.Error()}
	}

	if t.notifier != nil {
		if err := t.configureNotifierMode(ctx); err != nil {
			return clairerror.ErrNotInitialized{Msg: "could not configure notifier: " + err.Error()}
		}
	}

	return nil
}

// ConfigureIndexerMode configures the HttpTransport for IndexerMode.
//
// This mode runs only an Indexer in a single process.
func (t *Server) configureIndexerMode(ctx context.Context) error {
	// requires only indexer service
	if t.indexer == nil {
		return clairerror.ErrNotInitialized{Msg: "IndexerMode requires an indexer service"}
	}
	prefix := indexerRoot + apiRoot

	v1, err := NewIndexerV1(ctx, prefix, t.indexer, t.traceOpt)
	if err != nil {
		return fmt.Errorf("indexer configuration: %w", err)
	}
	var sem *semaphore.Weighted
	if ct := t.conf.Indexer.IndexReportRequestConcurrency; ct > 0 {
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
	t.Handle(prefix, rl)
	return nil
}

// ConfigureMatcherMode configures HttpTransport for MatcherMode.
//
// This mode runs only a Matcher in a single process.
func (t *Server) configureMatcherMode(ctx context.Context) error {
	// requires both an indexer and matcher service. indexer service
	// is assumed to be a remote call over the network
	if t.indexer == nil || t.matcher == nil {
		return clairerror.ErrNotInitialized{Msg: "MatcherMode requires both indexer and matcher services"}
	}
	prefix := matcherRoot + apiRoot
	v1 := NewMatcherV1(ctx, prefix, t.matcher, t.indexer, t.conf.Matcher.CacheAge, t.traceOpt)

	t.Handle(prefix, v1)
	return nil
}

// ConfigureNotifierMode configures HttpTransport for NotifierMode.
//
// This mode runs only a Notifier in a single process.
func (t *Server) configureNotifierMode(ctx context.Context) error {
	// requires both an indexer and matcher service. indexer service
	// is assumed to be a remote call over the network
	if t.notifier == nil {
		return clairerror.ErrNotInitialized{Msg: "NotifierMode requires a notifier service"}
	}

	t.Handle(NotificationAPIPath,
		intromw.InstrumentedHandler(NotificationAPIPath, t.traceOpt, NotificationHandler(t.notifier)))

	t.Handle(KeysAPIPath,
		intromw.InstrumentedHandler(KeysAPIPath, t.traceOpt, gone))

	t.Handle(KeyByIDAPIPath,
		intromw.InstrumentedHandler(KeyByIDAPIPath+"_KEY", t.traceOpt, gone))

	return nil
}

// IntraserviceIssuer is the issuer that will be used if Clair is configured to
// mint its own JWTs.
const IntraserviceIssuer = `clair-intraservice`

// ConfigureWithAuth will take the current serve mux and wrap it in an Auth
// middleware handler.
//
// Must be ran after the config*Mode method of choice.
func (t *Server) configureWithAuth(_ context.Context) error {
	h, err := authHandler(&t.conf, t.Server.Handler)
	if err != nil {
		return err
	}
	t.Server.Handler = h
	return nil
}

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
