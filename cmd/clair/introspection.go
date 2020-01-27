package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/pprof"
	"strings"

	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel/api/global"
	"go.opentelemetry.io/otel/api/key"
	"go.opentelemetry.io/otel/exporter/metric/dogstatsd"
	"go.opentelemetry.io/otel/exporter/metric/prometheus"
	"go.opentelemetry.io/otel/exporter/trace/jaeger"
	"go.opentelemetry.io/otel/exporter/trace/stdout"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"

	"github.com/quay/clair/v4/config"
)

const (
	HealthApiPath = "/healthz"
)

func introspection(ctx context.Context, cfg *config.Config, healthCheck func() bool) (*http.Server, error) {
	mux := http.NewServeMux()
	srv := http.Server{
		Addr: cfg.IntrospectionAddr,
	}
	log := zerolog.Ctx(ctx).With().Logger()

	// Metrics config
	if n := cfg.Metrics.Name; n != "" {
		log.Info().Str("sink", n).Msg("configuring metrics sink")
	}
	switch cfg.Metrics.Name {
	case "":
		log.Info().Str("sink", "default").Msg("configuring metrics sink")
		fallthrough
	case "prometheus":
		endpoint := "/metrics"
		if cfg.Metrics.Prometheus.Endpoint != nil {
			endpoint = *cfg.Metrics.Prometheus.Endpoint
		}
		log.Info().
			Str("endpoint", endpoint).
			Msg("configuring prometheus")
		promlog := log.With().
			Str("component", "metrics-exporter").
			Logger()
		pipeline, hf, err := prometheus.InstallNewPipeline(prometheus.Config{
			OnError: func(err error) {
				promlog.Error().Err(err).Msg("prometheus error")
			},
		})
		if err != nil {
			return nil, err
		}
		srv.RegisterOnShutdown(pipeline.Stop)
		mux.HandleFunc(endpoint, hf)
	case "dogstatsd":
		log.Info().
			Str("endpoint", cfg.Metrics.Dogstatsd.URL).
			Msg("configuring dogstatsd")
		pipeline, err := dogstatsd.InstallNewPipeline(dogstatsd.Config{
			URL: cfg.Metrics.Dogstatsd.URL,
		})
		if err != nil {
			return nil, err
		}
		srv.RegisterOnShutdown(pipeline.Stop)
	default:
	}

	// Trace config
	traceCfg := sdktrace.Config{
		// By default, assume an ingress is tagging incoming requests for
		// tracing.
		DefaultSampler: sdktrace.NeverSample(),
	}
	if cfg.Mode == config.DevMode {
		// Unless we're in dev mode, then go ham.
		traceCfg.DefaultSampler = sdktrace.AlwaysSample()
	}
	if p := cfg.Trace.Probability; p != nil {
		traceCfg.DefaultSampler = sdktrace.ProbabilitySampler(*p)
	}
	traceOpts := []sdktrace.ProviderOption{
		sdktrace.WithConfig(traceCfg),
	}
	if n := cfg.Trace.Name; n != "" {
		log.Info().Str("sink", n).Msg("configuring trace sink")
	}
Trace:
	switch cfg.Trace.Name {
	case "stdout":
		exporter, err := stdout.NewExporter(stdout.Options{})
		if err != nil {
			return nil, err
		}
		traceOpts = append(traceOpts, sdktrace.WithSyncer(exporter))
	case "jaeger":
		jcfg := &cfg.Trace.Jaeger
		var e jaeger.EndpointOption
		lev := log.Info()
		switch {
		case jcfg.Agent.Endpoint == "":
			jcfg.Agent.Endpoint = "localhost:6831"
			fallthrough
		case jcfg.Agent.Endpoint != "":
			lev = lev.Str("agent", jcfg.Agent.Endpoint)
			e = jaeger.WithAgentEndpoint(jcfg.Agent.Endpoint)
		case jcfg.Collector.Endpoint != "":
			var opt []jaeger.CollectorEndpointOption
			u, p := jcfg.Collector.Username, jcfg.Collector.Password
			if u != nil {
				lev = lev.Str("username", *u)
				opt = append(opt, jaeger.WithUsername(*u))
			}
			if p != nil {
				lev = lev.Str("password", strings.Repeat("*", len(*p)))
				opt = append(opt, jaeger.WithPassword(*p))
			}
			e = jaeger.WithCollectorEndpoint(jcfg.Collector.Endpoint, opt...)
		default:
			lev.Msg("neither jaeger collector nor agent specified")
			break Trace
		}

		jaegerlog := log.With().
			Str("component", "trace-exporter").
			Logger()
		opts := []jaeger.Option{
			jaeger.WithOnError(func(err error) {
				jaegerlog.Error().Err(err).Msg("jaeger error")
			}),
		}
		if jcfg.BufferMax != 0 {
			lev = lev.Int("buffer_max", jcfg.BufferMax)
			opts = append(opts, jaeger.WithBufferMaxCount(jcfg.BufferMax))
		}
		if jcfg.ServiceName == "" {
			jcfg.ServiceName = "clairv4/" + cfg.Mode
		}
		p := jaeger.Process{
			ServiceName: jcfg.ServiceName,
		}
		if len(jcfg.Tags) != 0 {
			d := zerolog.Dict()
			for k, v := range jcfg.Tags {
				d.Str(k, v)
				p.Tags = append(p.Tags, key.String(k, v))
			}
			lev = lev.Dict("tags", d)
		}
		opts = append(opts, jaeger.WithProcess(p))
		lev.Str("service_name", jcfg.ServiceName).
			Msg("configuring jaeger")
		exporter, err := jaeger.NewExporter(e, opts...)
		if err != nil {
			return nil, err
		}
		traceOpts = append(traceOpts, sdktrace.WithSyncer(exporter))
		srv.RegisterOnShutdown(exporter.Flush)
	default:
	}
	tp, err := sdktrace.NewProvider(traceOpts...)
	if err != nil {
		return nil, err
	}
	global.SetTraceProvider(tp)

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if !healthCheck() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		fmt.Fprint(w, `ok`)
	})
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	srv.Handler = mux
	return &srv, nil
}
