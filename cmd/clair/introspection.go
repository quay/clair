package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/pprof"

	"go.opentelemetry.io/otel/api/global"
	"go.opentelemetry.io/otel/exporter/metric/prometheus"
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
		Addr:        cfg.IntrospectionAddr,
		Handler:     mux,
		BaseContext: func(_ net.Listener) context.Context { return ctx },
	}

	// TODO Make configurable.
	pipeline, hf, err := prometheus.InstallNewPipeline(prometheus.Config{})
	if err != nil {
		return nil, err
	}
	srv.RegisterOnShutdown(pipeline.Stop)

	// TODO Make configurable.
	exporter, err := stdout.NewExporter(stdout.Options{PrettyPrint: true})
	if err != nil {
		return nil, err
	}
	tp, err := sdktrace.NewProvider(
		sdktrace.WithConfig(sdktrace.Config{DefaultSampler: sdktrace.NeverSample()}),
		sdktrace.WithSyncer(exporter))
	if err != nil {
		return nil, err
	}
	global.SetTraceProvider(tp)

	mux.HandleFunc("/metrics", hf)
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
	return &srv, nil
}
