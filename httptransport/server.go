package httptransport

import (
	"context"
	"fmt"
	"net"
	"net/http"

	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel/api/global"
	"go.opentelemetry.io/otel/plugin/othttp"

	clairerror "github.com/quay/clair/v4/clair-error"
	"github.com/quay/clair/v4/config"
	"github.com/quay/clair/v4/indexer"
	"github.com/quay/clair/v4/matcher"
	"github.com/quay/clair/v4/middleware/auth"
	intromw "github.com/quay/clair/v4/middleware/introspection"
)

const (
	apiRoot                 = "/api/v1/"
	internalRoot            = apiRoot + "internal/"
	VulnerabilityReportPath = apiRoot + "vulnerability_report/"
	IndexAPIPath            = apiRoot + "index_report"
	IndexReportAPIPath      = apiRoot + "index_report/"
	StateAPIPath            = apiRoot + "index_state"
	UpdatesAPIPath          = internalRoot + "updates/"
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
	traceOpt othttp.Option
}

func New(ctx context.Context, conf config.Config, indexer indexer.Service, matcher matcher.Service) (*Server, error) {
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
		traceOpt: othttp.WithTracer(global.TraceProvider().Tracer("clair")),
	}

	if err := t.configureDiscovery(); err != nil {
		log.Warn().Err(err).Msg("configuring openapi discovery failed")
	} else {
		log.Info().Str("path", OpenAPIV1Path).Msg("openapi discovery configured")
	}

	var e error
	switch conf.Mode {
	case config.ComboMode:
		e = t.configureComboMode()
		if e != nil {
			return nil, e
		}
		e = t.configureUpdateEndpoints()
		if e != nil {
			return nil, e
		}
	case config.IndexerMode:
		e = t.configureIndexerMode()
		if e != nil {
			return nil, e
		}
	case config.MatcherMode:
		e = t.configureMatcherMode()
		if e != nil {
			return nil, e
		}
		e = t.configureUpdateEndpoints()
		if e != nil {
			return nil, e
		}
	}

	// attach HttpTransport to server, this works because we embed http.ServeMux
	t.Server.Handler = t

	// add endpoint authentication if configured add auth. must happen after
	// mux was configured for given mode.
	if conf.Auth.Any() {
		err := t.configureWithAuth()
		if err != nil {
			log.Warn().Err(err).Msg("received error configuring auth middleware")
		}
	}

	return t, nil
}

// configureDiscovery() creates a discovery handler
// for serving the v1 open api specification
func (t *Server) configureDiscovery() error {
	h := intromw.Handler(
		othttp.NewHandler(
			DiscoveryHandler(),
			OpenAPIV1Path,
			t.traceOpt,
		),
		OpenAPIV1Path,
	)
	t.Handle(OpenAPIV1Path, othttp.WithRouteTag(OpenAPIV1Path, h))
	return nil
}

// configureDevMode configures the HttpTrasnport for
// DevMode.
//
// This mode runs both Indexer and Matcher in a single process.
func (t *Server) configureComboMode() error {
	// requires both indexer and matcher services
	if t.indexer == nil || t.matcher == nil {
		return clairerror.ErrNotInitialized{"DevMode requires both indexer and macher services"}
	}

	// vulnerability report handler register
	vulnReportH := intromw.Handler(
		othttp.NewHandler(
			VulnerabilityReportHandler(t.matcher, t.indexer),
			VulnerabilityReportPath,
			t.traceOpt,
		),
		VulnerabilityReportPath,
	)
	t.Handle(VulnerabilityReportPath, othttp.WithRouteTag(VulnerabilityReportPath, vulnReportH))

	// indexer handler register
	indexH := intromw.Handler(
		othttp.NewHandler(
			IndexHandler(t.indexer),
			IndexAPIPath,
			t.traceOpt,
		),
		IndexAPIPath,
	)
	t.Handle(IndexAPIPath, othttp.WithRouteTag(IndexAPIPath, indexH))

	// index report handler register
	indexReportH := intromw.Handler(
		othttp.NewHandler(
			IndexReportHandler(t.indexer),
			IndexReportAPIPath,
			t.traceOpt,
		),
		IndexReportAPIPath,
	)
	t.Handle(IndexReportAPIPath, othttp.WithRouteTag(IndexReportAPIPath, indexReportH))

	// state handler register
	stateH := intromw.Handler(
		othttp.NewHandler(
			StateHandler(t.indexer),
			StateAPIPath,
			t.traceOpt,
		),
		StateAPIPath,
	)
	t.Handle(StateAPIPath, othttp.WithRouteTag(StateAPIPath, stateH))

	return nil
}

// configureIndexerMode configures the HttpTransport for IndexerMode.
//
// This mode runs only an Indexer in a single process.
func (t *Server) configureIndexerMode() error {
	// requires only indexer service
	if t.indexer == nil {
		return clairerror.ErrNotInitialized{"IndexerMode requires an indexer service"}
	}

	// indexer handler register
	indexH := intromw.Handler(
		othttp.NewHandler(
			IndexHandler(t.indexer),
			IndexAPIPath,
			t.traceOpt,
		),
		IndexAPIPath,
	)
	t.Handle(IndexAPIPath, othttp.WithRouteTag(IndexAPIPath, indexH))

	// index report handler register
	indexReportH := intromw.Handler(
		othttp.NewHandler(
			IndexReportHandler(t.indexer),
			IndexReportAPIPath,
			t.traceOpt,
		),
		IndexReportAPIPath,
	)
	t.Handle(IndexReportAPIPath, othttp.WithRouteTag(IndexReportAPIPath, indexReportH))

	// state handler register
	stateH := intromw.Handler(
		othttp.NewHandler(
			StateHandler(t.indexer),
			StateAPIPath,
			t.traceOpt,
		),
		StateAPIPath,
	)
	t.Handle(StateAPIPath, othttp.WithRouteTag(StateAPIPath, stateH))

	return nil
}

// configureMatcherMode configures HttpTransport
func (t *Server) configureMatcherMode() error {
	// requires both an indexer and matcher service. indexer service
	// is assumed to be a remote call over the network
	if t.indexer == nil || t.matcher == nil {
		return clairerror.ErrNotInitialized{"MatcherMode requires both indexer and matcher services"}
	}

	// vulnerability report handler register
	vulnReportH := intromw.Handler(
		othttp.NewHandler(
			VulnerabilityReportHandler(t.matcher, t.indexer),
			VulnerabilityReportPath,
			t.traceOpt,
		),
		VulnerabilityReportPath,
	)
	t.Handle(VulnerabilityReportPath, othttp.WithRouteTag(VulnerabilityReportPath, vulnReportH))

	return nil
}

func (t *Server) configureUpdateEndpoints() error {
	if t.matcher == nil {
		return clairerror.ErrNotInitialized{"matcher service required for update inspection endpoints"}
	}

	h, err := UpdateDiffHandler(t.matcher)
	if err != nil {
		return err
	}
	wh := intromw.Handler(othttp.NewHandler(h, UpdatesAPIPath, t.traceOpt), UpdatesAPIPath)
	t.ServeMux.Handle(UpdatesAPIPath, othttp.WithRouteTag(UpdatesAPIPath, wh))

	return nil
}

// IntraserviceIssuer is the issuer that will be used if Clair is configured to
// mint its own JWTs.
const IntraserviceIssuer = `clair-intraservice`

// configureWithAuth will take the current serve mux and wrap it
// in an Auth middleware handler.
//
// must be ran after the config*Mode method of choice.
func (t *Server) configureWithAuth() error {
	// Keep this ordered "best" to "worst".
	switch {
	case t.conf.Auth.Keyserver != nil:
		cfg := t.conf.Auth.Keyserver
		checks := []auth.Checker{}
		ks, err := auth.NewQuayKeyserver(cfg.API)
		if err != nil {
			return fmt.Errorf("failed to initialize quay keyserver: %v", err)
		}
		checks = append(checks, ks)
		if cfg.Intraservice != nil {
			psk, err := auth.NewPSK(cfg.Intraservice, IntraserviceIssuer)
			if err != nil {
				return fmt.Errorf("failed to initialize quay keyserver: %w", err)
			}
			checks = append(checks, psk)
		}
		t.Server.Handler = auth.Handler(t.Server.Handler, checks...)
	case t.conf.Auth.PSK != nil:
		cfg := t.conf.Auth.PSK
		intra, err := auth.NewPSK(cfg.Key, IntraserviceIssuer)
		if err != nil {
			return err
		}
		psk, err := auth.NewPSK(cfg.Key, cfg.Issuer)
		if err != nil {
			return err
		}
		t.Server.Handler = auth.Handler(t.Server.Handler, intra, psk)
	default:
	}
	return nil
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
