package introspection

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/pprof"

	"github.com/quay/clair/v4/config"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"go.opentelemetry.io/otel/api/global"
	"go.opentelemetry.io/otel/api/key"
	"go.opentelemetry.io/otel/exporter/metric/dogstatsd"
	"go.opentelemetry.io/otel/exporter/metric/prometheus"
	"go.opentelemetry.io/otel/exporter/trace/jaeger"
	"go.opentelemetry.io/otel/exporter/trace/stdout"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

const (
	Prom                     = "prometheus"
	DefaultPromEndpoint      = "/metrics"
	DogStatsD                = "dogstatsd"
	STDOut                   = "stdout"
	Jaeger                   = "jaeger"
	DefaultJaegerEndpoint    = "localhost:6831"
	HealthEndpoint           = "/healthz"
	DefaultIntrospectionAddr = ":8089"
)

// Introspection provides an http server
// exposing Clair metrics and traces
type Introspection struct {
	// configuration provided when starting Clair
	conf config.Config
	// Introspection embeds a http.Server and http.ServeMux.
	// The http.Server will be configured with the ServeMux on successful
	// initialization.
	*http.Server
	*http.ServeMux
	// logger with context
	logger zerolog.Logger
	// a health check function
	health func() bool
}

func New(ctx context.Context, conf config.Config, health func() bool) (*Introspection, error) {
	logger := zerolog.Ctx(ctx).With().Str("component", "introspection").Logger()

	var addr string
	if conf.IntrospectionAddr == "" {
		addr = DefaultIntrospectionAddr
		logger.Info().Str("address", addr).Msg("no introspection address provied. using default addr")
	} else {
		addr = conf.IntrospectionAddr
	}

	i := &Introspection{
		conf: conf,
		Server: &http.Server{
			Addr:        addr,
			BaseContext: func(_ net.Listener) context.Context { return ctx },
		},
		ServeMux: http.NewServeMux(),
	}
	i.logger = logger

	// check for health
	if health == nil {
		i.logger.Warn().Msg("no health check configured. a default one will be used which simply returns OK")
		health = func() bool { return true }
	}

	// configure metrics
	logger.Info().Str("sink", conf.Metrics.Name).Msg("configuring")
	switch conf.Metrics.Name {
	case "", "default":
		logger.Info().Msg("no metrics sync enabled")
	case Prom:
		err := i.withPrometheus()
		if err != nil {
			return nil, err
		}
	case DogStatsD:
		err := i.withDogStatsD()
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
		sampler = sdktrace.ProbabilitySampler(p)
	default:
		sampler = sdktrace.NeverSample()
	}

	// trace exporter
	traceCfg := sdktrace.Config{
		DefaultSampler: sampler,
	}
	traceOpts := []sdktrace.ProviderOption{
		sdktrace.WithConfig(traceCfg),
	}
	switch conf.Trace.Name {
	case STDOut:
		err := i.withStdOut(traceOpts)
		if err != nil {
			return nil, fmt.Errorf("error configuring stdout tracing: %v", err)
		}
	case Jaeger:
		err := i.withJaeger(traceOpts)
		if err != nil {
			return nil, fmt.Errorf("error configuring jaeger tracing: %v", err)
		}
	default:
		logger.Info().Msg("no distributed tracing enabled")
	}

	// configure diagnostics
	err := i.withDiagnostics()
	if err != nil {
		return nil, fmt.Errorf("error configuring diagnostics: %v", err)
	}

	// attach Introspection to server, this works because we embed http.ServeMux
	i.Server.Handler = i

	return i, nil
}

// withDiagnotics enables healthz and pprof endpoints
func (i *Introspection) withDiagnostics() error {
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
func (i *Introspection) withStdOut(traceOpts []sdktrace.ProviderOption) error {
	exporter, err := stdout.NewExporter(stdout.Options{})
	if err != nil {
		return err
	}
	traceOpts = append(traceOpts, sdktrace.WithSyncer(exporter))
	tp, err := sdktrace.NewProvider(traceOpts...)
	if err != nil {
		return err
	}
	global.SetTraceProvider(tp)
	return nil
}

// withJaeger configures the Jaeger exporter for distributed tracing.
func (i *Introspection) withJaeger(traceOpts []sdktrace.ProviderOption) error {
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
		i.logger.Info().Str("endpoint", endpoint).Msg("configuring jaeger exporter to push to agent")
		e = jaeger.WithAgentEndpoint(endpoint)
	case "collector":
		i.logger.Info().Str("endpoint", endpoint).Msg("configuring jaeger exporter to push to collector")
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
	component := fmt.Sprintf("jaeger-exporter:%v", endpoint)
	jaegerLog := log.With().Str("component", component).Logger()
	opts := []jaeger.Option{
		jaeger.WithOnError(func(err error) {
			jaegerLog.Error().Err(err).Msg("jaeger-exporter error")
		}),
	}
	if conf.BufferMax != 0 {
		opts = append(opts, jaeger.WithBufferMaxCount(conf.BufferMax))
	}
	p := jaeger.Process{
		ServiceName: "clairv4/" + i.conf.Mode,
	}
	if len(conf.Tags) != 0 {
		for k, v := range conf.Tags {
			p.Tags = append(p.Tags, key.String(k, v))
		}
	}
	opts = append(opts, jaeger.WithProcess(p))
	exporter, err := jaeger.NewExporter(e, opts...)
	if err != nil {
		return err
	}
	traceOpts = append(traceOpts, sdktrace.WithSyncer(exporter))

	i.RegisterOnShutdown(exporter.Flush)

	tp, err := sdktrace.NewProvider(traceOpts...)
	if err != nil {
		return err
	}
	global.SetTraceProvider(tp)
	return nil
}

// withDogStatsD configures a dogstatsd open telemetry
// pipeline.
func (i *Introspection) withDogStatsD() error {
	if i.conf.Metrics.Dogstatsd.URL == "" {
		return fmt.Errorf("dogstatsd metrics were specified but no url was configured")
	}
	log.Info().
		Str("endpoint", i.conf.Metrics.Dogstatsd.URL).
		Msg("configuring dogstatsd")
	pipeline, err := dogstatsd.InstallNewPipeline(dogstatsd.Config{
		URL: i.conf.Metrics.Dogstatsd.URL,
	})
	if err != nil {
		return fmt.Errorf("failed to create dogstatsd pipeline: %v", err)
	}
	i.RegisterOnShutdown(pipeline.Stop)
	return nil
}

// withPrometheus configures a prometheus open telemetry
// pipeline, registers it with the server, and adds the prometheus
// endpoint to i's servemux.
func (i *Introspection) withPrometheus() error {
	endpoint := DefaultPromEndpoint
	if i.conf.Metrics.Prometheus.Endpoint != nil {
		endpoint = *i.conf.Metrics.Prometheus.Endpoint
	}

	i.logger.Info().Str("endpoint", endpoint).
		Str("server", i.Addr).
		Msg("configuring prometheus with endpoint")

	promlog := log.With().Str("component", "promtheus-metrics-exporter").Logger()
	pipeline, hr, err := prometheus.InstallNewPipeline(prometheus.Config{
		OnError: func(err error) {
			promlog.Error().Err(err).Msg("prometheus error")
		},
	})
	if err != nil {
		return err
	}

	i.RegisterOnShutdown(pipeline.Stop)
	i.HandleFunc(endpoint, hr)
	return nil
}
