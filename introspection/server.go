package introspection

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/pprof"

	"github.com/rs/zerolog"
	"go.opentelemetry.io/contrib/exporters/metric/dogstatsd"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/metric/prometheus"
	"go.opentelemetry.io/otel/exporters/stdout"
	"go.opentelemetry.io/otel/exporters/trace/jaeger"
	"go.opentelemetry.io/otel/label"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"

	"github.com/quay/clair/v4/config"
)

const (
	Prom                     = "prometheus"
	DefaultPromEndpoint      = "/metrics"
	DogStatsD                = "dogstatsd"
	Stdout                   = "stdout"
	Jaeger                   = "jaeger"
	DefaultJaegerEndpoint    = "localhost:6831"
	HealthEndpoint           = "/healthz"
	DefaultIntrospectionAddr = ":8089"
)

// Server provides an http server
// exposing Clair metrics and traces
type Server struct {
	// configuration provided when starting Clair
	conf config.Config
	// Server embeds a http.Server and http.ServeMux.
	// The http.Server will be configured with the ServeMux on successful
	// initialization.
	*http.Server
	*http.ServeMux
	// a health check function
	health func() bool
}

func New(ctx context.Context, conf config.Config, health func() bool) (*Server, error) {
	logger := zerolog.Ctx(ctx).With().Str("component", "introspection").Logger()

	var addr string
	if conf.IntrospectionAddr == "" {
		addr = DefaultIntrospectionAddr
		logger.Info().Str("address", addr).Msg("no introspection address provied. using default")
	} else {
		addr = conf.IntrospectionAddr
	}

	i := &Server{
		conf: conf,
		Server: &http.Server{
			Addr:        addr,
			BaseContext: func(_ net.Listener) context.Context { return ctx },
		},
		ServeMux: http.NewServeMux(),
	}

	// check for health
	if health == nil {
		logger.Warn().Msg("no health check configured; unconditionally reporting OK")
		i.health = func() bool { return true }
	}

	// configure metrics
	logger.Info().Str("sink", conf.Metrics.Name).Msg("configuring")
	switch conf.Metrics.Name {
	case "", "default":
		logger.Info().Msg("no metrics sync enabled")
	case Prom:
		err := i.withPrometheus(ctx)
		if err != nil {
			return nil, err
		}
	case DogStatsD:
		err := i.withDogStatsD(ctx)
		if err != nil {
			return nil, err
		}
	}

	// configure tracing
	// sampler
	var sampler sdktrace.Sampler
	switch {
	case i.conf.LogLevel == "debug":
		sampler = sdktrace.AlwaysSample()
	case i.conf.Trace.Probability != nil:
		p := *i.conf.Trace.Probability
		sampler = sdktrace.ParentBased(
			sdktrace.TraceIDRatioBased(p),
		)
	default:
		sampler = sdktrace.NeverSample()
	}

	// trace exporter
	traceCfg := sdktrace.Config{
		DefaultSampler: sampler,
	}
	traceOpts := []sdktrace.TracerProviderOption{
		sdktrace.WithConfig(traceCfg),
	}
	switch conf.Trace.Name {
	case Stdout:
		err := i.withStdOut(ctx, traceOpts)
		if err != nil {
			return nil, fmt.Errorf("error configuring stdout tracing: %v", err)
		}
	case Jaeger:
		err := i.withJaeger(ctx, traceOpts)
		if err != nil {
			return nil, fmt.Errorf("error configuring jaeger tracing: %v", err)
		}
	default:
		logger.Info().Msg("no distributed tracing enabled")
	}

	// configure diagnostics
	err := i.withDiagnostics(ctx)
	if err != nil {
		return nil, fmt.Errorf("error configuring diagnostics: %v", err)
	}

	// attach Introspection to server, this works because we embed http.ServeMux
	i.Server.Handler = i

	return i, nil
}

// withDiagnotics enables healthz and pprof endpoints
func (i *Server) withDiagnostics(_ context.Context) error {
	health := i.health
	i.HandleFunc(HealthEndpoint, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if !health() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		fmt.Fprint(w, `ok`)
	})
	i.HandleFunc("/debug/pprof/", pprof.Index)
	i.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	i.HandleFunc("/debug/pprof/profile", pprof.Profile)
	i.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	i.HandleFunc("/debug/pprof/trace", pprof.Trace)
	return nil
}

// withStdOut configures the stdout exporter for distributed tracing
func (i *Server) withStdOut(_ context.Context, traceOpts []sdktrace.TracerProviderOption) error {
	exporter, err := stdout.NewExporter()
	if err != nil {
		return err
	}
	traceOpts = append(traceOpts, sdktrace.WithSyncer(exporter))
	tp := sdktrace.NewTracerProvider(traceOpts...)
	otel.SetTracerProvider(tp)
	return nil
}

// withJaeger configures the Jaeger exporter for distributed tracing.
func (i *Server) withJaeger(ctx context.Context, traceOpts []sdktrace.TracerProviderOption) error {
	logger := zerolog.Ctx(ctx).With().
		Str("component", "introspection/Introspection.withJaeger").
		Logger()
	conf := i.conf.Trace.Jaeger
	var mode string
	var endpoint string

	// configure whether jaeger exporter pushes to an agent
	// or a collector
	switch {
	case conf.Agent.Endpoint != "":
		mode = "agent"
		endpoint = conf.Agent.Endpoint
	case conf.Collector.Endpoint != "":
		mode = "collector"
		endpoint = conf.Collector.Endpoint
	default:
		mode = "agent"
		endpoint = DefaultJaegerEndpoint
	}

	var e jaeger.EndpointOption
	switch mode {
	case "agent":
		logger.Info().Str("endpoint", endpoint).Msg("configuring jaeger exporter to push to agent")
		e = jaeger.WithAgentEndpoint(endpoint)
	case "collector":
		logger.Info().Str("endpoint", endpoint).Msg("configuring jaeger exporter to push to collector")
		var opt []jaeger.CollectorEndpointOption
		u, p := conf.Collector.Username, conf.Collector.Password
		if u != nil {
			opt = append(opt, jaeger.WithUsername(*u))
		}
		if p != nil {
			opt = append(opt, jaeger.WithPassword(*p))
		}
		e = jaeger.WithCollectorEndpoint(endpoint, opt...)
	}

	// configure the exporter
	opts := []jaeger.Option{}
	if conf.BufferMax != 0 {
		opts = append(opts, jaeger.WithBufferMaxCount(conf.BufferMax))
	}
	p := jaeger.Process{
		ServiceName: "clairv4/" + i.conf.Mode,
	}
	if len(conf.Tags) != 0 {
		for k, v := range conf.Tags {
			p.Tags = append(p.Tags, label.String(k, v))
		}
	}
	opts = append(opts, jaeger.WithProcess(p))
	exporter, err := jaeger.NewRawExporter(e, opts...)
	if err != nil {
		return err
	}
	traceOpts = append(traceOpts, sdktrace.WithSyncer(exporter))

	i.RegisterOnShutdown(exporter.Flush)

	tp := sdktrace.NewTracerProvider(traceOpts...)
	if err != nil {
		return err
	}
	otel.SetTracerProvider(tp)
	return nil
}

// withDogStatsD configures a dogstatsd open telemetry
// pipeline.
func (i *Server) withDogStatsD(ctx context.Context) error {
	if i.conf.Metrics.Dogstatsd.URL == "" {
		return fmt.Errorf("dogstatsd metrics were specified but no url was configured")
	}
	logger := zerolog.Ctx(ctx).With().
		Str("component", "introspection/Introspection.withDogStatsD").
		Logger()

	logger.Info().
		Str("endpoint", i.conf.Metrics.Dogstatsd.URL).
		Msg("configuring dogstatsd")

	pipeline, err := dogstatsd.InstallNewPipeline(dogstatsd.Config{
		URL: i.conf.Metrics.Dogstatsd.URL,
	})
	if err != nil {
		return fmt.Errorf("failed to create dogstatsd pipeline: %v", err)
	}
	i.RegisterOnShutdown(
		func() {
			pipeline.Stop(ctx)
		})
	return nil
}

// withPrometheus configures a prometheus open telemetry
// pipeline, registers it with the server, and adds the prometheus
// endpoint to i's servemux.
func (i *Server) withPrometheus(ctx context.Context) error {
	logger := zerolog.Ctx(ctx).With().
		Str("component", "introspection/Introspection.withPrometheus").
		Logger()

	endpoint := DefaultPromEndpoint
	if i.conf.Metrics.Prometheus.Endpoint != nil {
		endpoint = *i.conf.Metrics.Prometheus.Endpoint
	}
	logger.Info().Str("endpoint", endpoint).
		Str("server", i.Addr).
		Msg("configuring prometheus")

	pipeline, err := prometheus.InstallNewPipeline(prometheus.Config{})
	if err != nil {
		return err
	}

	i.RegisterOnShutdown(func() {
		pipeline.Controller().Stop(ctx)
	})
	i.HandleFunc(endpoint, pipeline.ServeHTTP)
	return nil
}
