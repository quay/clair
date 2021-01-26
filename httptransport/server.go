package httptransport

import (
	"context"
	"net"
	"net/http"

	"github.com/rs/zerolog"
	othttp "go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"

	clairerror "github.com/quay/clair/v4/clair-error"
	"github.com/quay/clair/v4/config"
	"github.com/quay/clair/v4/indexer"
	"github.com/quay/clair/v4/matcher"
	intromw "github.com/quay/clair/v4/middleware/introspection"
	notifier "github.com/quay/clair/v4/notifier/service"
)

const (
	apiRoot                 = "/api/v1/"
	indexerRoot             = "/indexer"
	matcherRoot             = "/matcher"
	notifierRoot            = "/notifier"
	internalRoot            = apiRoot + "internal/"
	IndexAPIPath            = indexerRoot + apiRoot + "index_report"
	IndexReportAPIPath      = indexerRoot + apiRoot + "index_report/"
	IndexStateAPIPath       = indexerRoot + apiRoot + "index_state"
	AffectedManifestAPIPath = indexerRoot + internalRoot + "affected_manifest/"
	VulnerabilityReportPath = matcherRoot + apiRoot + "vulnerability_report/"
	UpdateOperationAPIPath  = matcherRoot + internalRoot + "update_operation/"
	UpdateDiffAPIPath       = matcherRoot + internalRoot + "update_diff/"
	NotificationAPIPath     = notifierRoot + apiRoot + "notification/"
	KeysAPIPath             = notifierRoot + apiRoot + "services/notifier/keys"
	KeyByIDAPIPath          = notifierRoot + apiRoot + "services/notifier/keys/"
	OpenAPIV1Path           = "/openapi/v1"
)

// Server is the primary http server
// Clair exposes it's functionality on.
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
	log := zerolog.Ctx(ctx).With().
		Str("component", "init/NewHttpTransport").
		Logger()
	ctx = log.WithContext(ctx)

	serv := &http.Server{
		Addr: conf.HTTPListenAddr,
		// use the passed in global context as the base context
		// for all http requests handled by this server
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

	if err := t.configureDiscovery(ctx); err != nil {
		log.Warn().Err(err).Msg("configuring openapi discovery failed")
	} else {
		log.Info().Str("path", OpenAPIV1Path).Msg("openapi discovery configured")
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

	// add endpoint authentication if configured add auth. must happen after
	// mux was configured for given mode.
	if conf.Auth.Any() {
		err := t.configureWithAuth(ctx)
		if err != nil {
			log.Warn().Err(err).Msg("received error configuring auth middleware")
		}
	}

	return t, nil
}

// configureDiscovery() creates a discovery handler
// for serving the v1 open api specification
func (t *Server) configureDiscovery(_ context.Context) error {
	h := intromw.Handler(
		othttp.NewHandler(
			LoggingHandler(DiscoveryHandler()),
			OpenAPIV1Path,
			t.traceOpt,
		),
		OpenAPIV1Path,
	)
	t.Handle(OpenAPIV1Path, othttp.WithRouteTag(OpenAPIV1Path, h))
	return nil
}

// configureDevMode configures the HttpTrasnport for
// ComboMode.
//
// This mode runs both Indexer and Matcher in a single process.
func (t *Server) configureComboMode(ctx context.Context) error {
	// requires both indexer and matcher services
	if t.indexer == nil || t.matcher == nil {
		return clairerror.ErrNotInitialized{"Combo mode requires both indexer and macher services"}
	}

	err := t.configureIndexerMode(ctx)
	if err != nil {
		return clairerror.ErrNotInitialized{"could not configure indexer: " + err.Error()}
	}

	err = t.configureMatcherMode(ctx)
	if err != nil {
		return clairerror.ErrNotInitialized{"could not configure matcher: " + err.Error()}
	}

	err = t.configureNotifierMode(ctx)
	if err != nil {
		return clairerror.ErrNotInitialized{"could not configure notifier: " + err.Error()}
	}

	return nil
}

// configureIndexerMode configures the HttpTransport for IndexerMode.
//
// This mode runs only an Indexer in a single process.
func (t *Server) configureIndexerMode(_ context.Context) error {
	// requires only indexer service
	if t.indexer == nil {
		return clairerror.ErrNotInitialized{"IndexerMode requires an indexer service"}
	}

	// affected manifest handler register
	affectedH := intromw.Handler(
		othttp.NewHandler(
			LoggingHandler(AffectedManifestHandler(t.indexer)),
			AffectedManifestAPIPath,
			t.traceOpt,
		),
		AffectedManifestAPIPath,
	)
	t.Handle(AffectedManifestAPIPath, othttp.WithRouteTag(AffectedManifestAPIPath, affectedH))

	// index handler register
	indexH := intromw.Handler(
		othttp.NewHandler(
			LoggingHandler(IndexHandler(t.indexer)),
			IndexAPIPath,
			t.traceOpt,
		),
		IndexAPIPath,
	)
	t.Handle(IndexAPIPath, othttp.WithRouteTag(IndexAPIPath, indexH))

	// index report handler register
	indexReportH := intromw.Handler(
		othttp.NewHandler(
			LoggingHandler(IndexReportHandler(t.indexer)),
			IndexReportAPIPath,
			t.traceOpt,
		),
		IndexReportAPIPath,
	)
	t.Handle(IndexReportAPIPath, othttp.WithRouteTag(IndexReportAPIPath, indexReportH))

	// index state handler register
	stateH := intromw.Handler(
		othttp.NewHandler(
			LoggingHandler(IndexStateHandler(t.indexer)),
			IndexStateAPIPath,
			t.traceOpt,
		),
		IndexStateAPIPath,
	)
	t.Handle(IndexStateAPIPath, othttp.WithRouteTag(IndexStateAPIPath, stateH))

	return nil
}

// configureMatcherMode configures HttpTransport
func (t *Server) configureMatcherMode(_ context.Context) error {
	// requires both an indexer and matcher service. indexer service
	// is assumed to be a remote call over the network
	if t.indexer == nil || t.matcher == nil {
		return clairerror.ErrNotInitialized{"MatcherMode requires both indexer and matcher services"}
	}

	// vulnerability report handler register
	vulnReportH := intromw.Handler(
		othttp.NewHandler(
			LoggingHandler(VulnerabilityReportHandler(t.matcher, t.indexer)),
			VulnerabilityReportPath,
			t.traceOpt,
		),
		VulnerabilityReportPath,
	)
	t.Handle(VulnerabilityReportPath, othttp.WithRouteTag(VulnerabilityReportPath, vulnReportH))

	// update operation handler register
	opH := intromw.Handler(
		othttp.NewHandler(
			LoggingHandler(UpdateOperationHandler(t.matcher)),
			UpdateOperationAPIPath,
			t.traceOpt,
		),
		UpdateOperationAPIPath,
	)
	t.Handle(UpdateOperationAPIPath, othttp.WithRouteTag(UpdateOperationAPIPath, opH))

	// update diff handler register
	diffH := intromw.Handler(
		othttp.NewHandler(
			LoggingHandler(UpdateDiffHandler(t.matcher)),
			UpdateDiffAPIPath,
			t.traceOpt,
		),
		UpdateDiffAPIPath,
	)
	t.Handle(UpdateDiffAPIPath, othttp.WithRouteTag(UpdateDiffAPIPath, diffH))

	return nil
}

// configureMatcherMode configures HttpTransport
func (t *Server) configureNotifierMode(ctx context.Context) error {
	// requires both an indexer and matcher service. indexer service
	// is assumed to be a remote call over the network
	if t.notifier == nil {
		return clairerror.ErrNotInitialized{"NotifierMode requires a notifier service"}
	}

	// notifications callback handler
	callbackH := intromw.Handler(
		othttp.NewHandler(
			LoggingHandler(NotificationHandler(t.notifier)),
			NotificationAPIPath,
			t.traceOpt,
		),
		NotificationAPIPath,
	)
	t.Handle(NotificationAPIPath, othttp.WithRouteTag(NotificationAPIPath, callbackH))

	ks := t.notifier.KeyStore(ctx)
	if ks == nil {
		return clairerror.ErrNotInitialized{"NotifierMode requires the notifier to provide a non-nil key store"}
	}

	// keys handler
	keysH := intromw.Handler(
		othttp.NewHandler(
			LoggingHandler(KeysHandler(ks)),
			KeysAPIPath,
			t.traceOpt,
		),
		KeysAPIPath,
	)
	t.Handle(KeysAPIPath, othttp.WithRouteTag(KeysAPIPath, keysH))

	// key by ID handler
	keyByIDH := intromw.Handler(
		othttp.NewHandler(
			LoggingHandler(KeyByIDHandler(ks)),
			KeyByIDAPIPath,
			t.traceOpt,
		),
		KeyByIDAPIPath,
	)
	t.Handle(KeyByIDAPIPath, othttp.WithRouteTag(KeyByIDAPIPath, keyByIDH))

	return nil
}

// IntraserviceIssuer is the issuer that will be used if Clair is configured to
// mint its own JWTs.
const IntraserviceIssuer = `clair-intraservice`

// configureWithAuth will take the current serve mux and wrap it
// in an Auth middleware handler.
//
// must be ran after the config*Mode method of choice.
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

// writerError is a helper that closes over an error that may be returned after
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
