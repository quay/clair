// Package introspection holds the implementation details for the
// "introspection" HTTP server that Clair hosts.
package introspection

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/pprof"
	"time"

	deltapprof "github.com/grafana/pyroscope-go/godeltaprof/http/pprof"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/quay/clair/config"
	"github.com/quay/zlog"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/jaeger"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/exporters/stdout/stdoutmetric"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.27.0"

	"github.com/quay/clair/v4/health"
)

// Valid backends for both metrics and traces.
const (
	Stdout = "stdout"
	OTLP   = "otlp"
)

// Valid backends for metrics.
const (
	Prom = "prometheus"
)

// Valid backends for traces.
const (
	Jaeger = "jaeger"
)

// Endpoints on the introspection HTTP server.
const (
	DefaultPromEndpoint = "/metrics"
	HealthEndpoint      = "/healthz"
	ReadyEndpoint       = "/readyz"
)

// DefaultIntrospectionAddr is the default address if not provided in the configuration.
const DefaultIntrospectionAddr = ":8089"

// Server provides an HTTP server exposing Clair metrics and debugging information.
type Server struct {
	// configuration provided when starting Clair
	conf *config.Config
	// Server embeds a http.Server and http.ServeMux.
	// The http.Server will be configured with the ServeMux on successful
	// initialization.
	*http.Server
	*http.ServeMux
	// a health check function
	health func() bool
}

// New constructs a [*Server], which has an embedded [*http.Server].
func New(ctx context.Context, conf *config.Config, health func() bool) (*Server, error) {
	var err error
	ctx = zlog.ContextWithValues(ctx, "component", "introspection/New")

	var addr string
	if conf.IntrospectionAddr == "" {
		addr = DefaultIntrospectionAddr
		zlog.Info(ctx).
			Str("address", addr).
			Msg("no introspection address provided; using default")
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
		zlog.Warn(ctx).Msg("no health check configured; unconditionally reporting OK")
		i.health = func() bool { return true }
	} else {
		i.health = health
	}

	// Configure metrics
	var mr metric.Reader
	switch conf.Metrics.Name {
	case Stdout:
		var ex metric.Exporter
		ex, err = stdoutmetric.New()
		if err != nil {
			break
		}
		mr = metric.NewPeriodicReader(ex)
	case Prom, "":
		endpoint := DefaultPromEndpoint
		if p := conf.Metrics.Prometheus.Endpoint; p != nil {
			endpoint = *p
		}
		zlog.Info(ctx).
			Str("endpoint", endpoint).
			Str("server", i.Addr).
			Msg("configuring prometheus")

		i.Handle(endpoint, promhttp.Handler())

		mr, err = prometheus.New()
	case OTLP:
		conf := i.conf.Trace.OTLP
		if conf.GRPC == nil && conf.HTTP == nil {
			return nil, fmt.Errorf(`must define either "grpc" or "http" transport for otlp traces`)
		}

		var ex metric.Exporter
		switch {
		case conf.GRPC != nil:
			var opts []otlpmetricgrpc.Option
			opts, err = omgHooks.Options(conf.GRPC)
			if err != nil {
				break
			}
			ex, err = otlpmetricgrpc.New(ctx, opts...)
		case conf.HTTP != nil:
			var opts []otlpmetrichttp.Option
			opts, err = omhHooks.Options(conf.HTTP)
			if err != nil {
				break
			}
			ex, err = otlpmetrichttp.New(ctx, opts...)
		default:
			panic("programmer error: exhaustive switch")
		}
		if err != nil {
			break
		}

		// Print a warning as long as direct prometheus metrics exist in "our" packages.
		zlog.Warn(ctx).Msg("OTLP metrics should be considered beta; metrics may be missing")
		mr = metric.NewPeriodicReader(ex)
	default:
		zlog.Info(ctx).Msg("no metrics enabled")
	}
	if err != nil {
		return nil, fmt.Errorf("error configuring metrics: %w", err)
	}
	if mr != nil {
		mp := metric.NewMeterProvider(
			metric.WithReader(mr),
			metric.WithResource(resource.NewWithAttributes(
				semconv.SchemaURL,
				semconv.ServiceNameKey.String(fmt.Sprintf("clairv4/%v", i.conf.Mode)),
			)),
		)
		otel.SetMeterProvider(mp)
		i.Server.RegisterOnShutdown(func() {
			ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			if err := mp.Shutdown(ctx); err != nil {
				zlog.Error(ctx).Err(err).Msg("error shutting down metric provider")
			}
		})
	}

	// configure tracing
	// sampler
	var sampler sdktrace.Sampler
	switch {
	case i.conf.LogLevel == config.DebugLog || i.conf.LogLevel == config.DebugColorLog:
		sampler = sdktrace.AlwaysSample()
	case i.conf.Trace.Probability != nil:
		p := *i.conf.Trace.Probability
		sampler = sdktrace.ParentBased(
			sdktrace.TraceIDRatioBased(p),
		)
	default:
		sampler = sdktrace.ParentBased(sdktrace.NeverSample())
	}

	// trace exporter
	var exporter sdktrace.SpanExporter
	switch conf.Trace.Name {
	case Stdout:
		exporter, err = stdouttrace.New()
	case Jaeger:
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
		}

		var e jaeger.EndpointOption
		switch mode {
		case "agent":
			zlog.Info(ctx).Msg("configuring jaeger exporter to push to agent")
			var opt []jaeger.AgentEndpointOption
			if endpoint != "" {
				host, port, err := net.SplitHostPort(endpoint)
				if err != nil {
					return nil, fmt.Errorf("error configuring jaeger tracing: %w", err)
				}
				if host != "" {
					opt = append(opt, jaeger.WithAgentHost(host))
				}
				if port != "" {
					opt = append(opt, jaeger.WithAgentPort(port))
				}
			}
			e = jaeger.WithAgentEndpoint(opt...)
		case "collector":
			zlog.Info(ctx).Msg("configuring jaeger exporter to push to collector")
			var opt []jaeger.CollectorEndpointOption
			if endpoint != "" {
				opt = append(opt, jaeger.WithEndpoint(endpoint))
			}
			u, p := conf.Collector.Username, conf.Collector.Password
			if u != nil {
				opt = append(opt, jaeger.WithUsername(*u))
			}
			if p != nil {
				opt = append(opt, jaeger.WithPassword(*p))
			}
			e = jaeger.WithCollectorEndpoint(opt...)
		}

		// configure the exporter
		exporter, err = jaeger.New(e)
	case OTLP:
		conf := i.conf.Trace.OTLP
		if conf.GRPC == nil && conf.HTTP == nil {
			return nil, fmt.Errorf(`must define either "grpc" or "http" transport for otlp traces`)
		}

		var c otlptrace.Client
		switch {
		case conf.GRPC != nil:
			var opts []otlptracegrpc.Option
			opts, err = otgHooks.Options(conf.GRPC)
			if err != nil {
				break
			}
			c = otlptracegrpc.NewClient(opts...)
		case conf.HTTP != nil:
			var opts []otlptracehttp.Option
			opts, err = othHooks.Options(conf.HTTP)
			if err != nil {
				break
			}
			c = otlptracehttp.NewClient(opts...)
		default:
			panic("programmer error: exhaustive switch")
		}
		if err != nil {
			break
		}

		exporter, err = otlptrace.New(ctx, c)
	default:
		zlog.Info(ctx).Msg("no distributed tracing enabled")
	}
	if err != nil {
		return nil, fmt.Errorf("error configuring tracing: %w", err)
	}
	if exporter != nil {
		tp := sdktrace.NewTracerProvider(
			sdktrace.WithSampler(sampler),
			sdktrace.WithBatcher(exporter),
			sdktrace.WithResource(resource.NewWithAttributes(
				semconv.SchemaURL,
				semconv.ServiceNameKey.String(fmt.Sprintf("clairv4/%v", i.conf.Mode)),
			)),
		)
		otel.SetTracerProvider(tp)
		i.Server.RegisterOnShutdown(func() {
			zlog.Info(ctx).Msg("shutting down trace provider")
			ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer cancel()
			if err := tp.Shutdown(ctx); err != nil {
				zlog.Error(ctx).Err(err).Msg("error shutting down trace provider")
			}
		})
		zlog.Info(ctx).Msg("distributed tracing configured")
	}

	// configure diagnostics
	err = i.withDiagnostics(ctx)
	if err != nil {
		return nil, fmt.Errorf("error configuring diagnostics: %v", err)
	}
	if err := i.withReady(ctx); err != nil {
		return nil, fmt.Errorf("error configuring ready: %v", err)
	}

	// attach Introspection to server, this works because we embed http.ServeMux
	i.Server.Handler = i

	return i, nil
}

// WithDiagnostics enables healthz and pprof endpoints.
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
	i.HandleFunc("/debug/pprof/delta_heap", deltapprof.Heap)
	i.HandleFunc("/debug/pprof/delta_block", deltapprof.Block)
	i.HandleFunc("/debug/pprof/delta_mutex", deltapprof.Mutex)
	return nil
}

func (i *Server) withReady(_ context.Context) error {
	i.ServeMux.Handle(ReadyEndpoint, health.ReadinessHandler())
	return nil
}
