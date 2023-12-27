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
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.7.0"

	"github.com/quay/clair/v4/health"
)

const (
	Prom                     = "prometheus"
	DefaultPromEndpoint      = "/metrics"
	Stdout                   = "stdout"
	Jaeger                   = "jaeger"
	HealthEndpoint           = "/healthz"
	ReadyEndpoint            = "/readyz"
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

	// configure prometheus
	err := i.withPrometheus(ctx)
	if err != nil {
		return nil, fmt.Errorf("error configuring prometheus handler: %v", err)
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
		sampler = sdktrace.NeverSample()
	}

	// trace exporter
	var exporter sdktrace.SpanExporter
	switch conf.Trace.Name {
	case Stdout:
		exporter, err = stdouttrace.New()
		if err != nil {
			return nil, fmt.Errorf("error configuring stdout tracing: %w", err)
		}
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
		if err != nil {
			return nil, fmt.Errorf("error configuring jaeger tracing: %w", err)
		}
	default:
		zlog.Info(ctx).Msg("no distributed tracing enabled")
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
			ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
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

// WithPrometheus adds the prometheus endpoint to i's ServeMux.
func (i *Server) withPrometheus(ctx context.Context) error {
	ctx = zlog.ContextWithValues(ctx, "component", "introspection/Server.withPrometheus")
	endpoint := DefaultPromEndpoint
	if i.conf.Metrics.Prometheus.Endpoint != nil {
		endpoint = *i.conf.Metrics.Prometheus.Endpoint
	}
	zlog.Info(ctx).
		Str("endpoint", endpoint).
		Str("server", i.Addr).
		Msg("configuring prometheus")

	i.Handle(endpoint, promhttp.Handler())
	return nil
}
