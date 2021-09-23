package introspection

import (
	"net/http"
	"strings"

	rr "github.com/ldelossa/responserecorder"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/quay/zlog"
	othttp "go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

const (
	Namespace = "clair"
	Subsystem = "http"
)

// InstrumentedHandler performs all instrumentation for a Clair HTTP handler
//
// This includes prometheus metrics, logging, and otel distributed tracing.
func InstrumentedHandler(endpoint string, traceOpts othttp.Option, next http.Handler) http.Handler {
	endpoint = normalizePath(endpoint)
	var (
		RequestCount = prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: Namespace,
				Subsystem: Subsystem,
				Name:      endpoint + "_request_total",
				Help:      "A total count of http requests for the given path",
			},
			[]string{"code", "method"},
		)
		RequestSize = prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: Namespace,
				Subsystem: Subsystem,
				Name:      endpoint + "_request_size_bytes",
				Help:      "Distribution of request sizes for the given path",
			},
			[]string{},
		)
		ResponseSize = prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: Namespace,
				Subsystem: Subsystem,
				Name:      endpoint + "_response_size_bytes",
				Help:      "Distribution of response sizes for the given path",
			}, []string{},
		)
		RequestDuration = prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: Namespace,
				Subsystem: Subsystem,
				Name:      endpoint + "_request_duration_seconds",
				Help:      "Distribution of request durations for the given path",
			}, []string{},
		)
	)
	prometheus.MustRegister(RequestCount, RequestSize, ResponseSize, RequestDuration)
	var h http.Handler
	h = othttp.NewHandler(next, endpoint, traceOpts)
	h = othttp.WithRouteTag(endpoint, h)
	h = promhttp.InstrumentHandlerCounter(RequestCount, next)
	h = promhttp.InstrumentHandlerRequestSize(RequestSize, h)
	h = promhttp.InstrumentHandlerResponseSize(ResponseSize, h)
	h = promhttp.InstrumentHandlerTimeToWriteHeader(RequestDuration, h)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recorder := rr.NewResponseRecorder(w)
		h.ServeHTTP(recorder, r)
		zlog.Info(r.Context()).
			Str("remote_addr", r.RemoteAddr).
			Str("method", r.Method).
			Str("request_uri", r.RequestURI).
			Int("status", recorder.StatusCode()).
			Msg("handled HTTP request")
	})
}

// normalizePath creates a path usable as a Prometheus metric.
func normalizePath(path string) string {
	path = strings.Replace(path, "/", "_", -1)
	path = strings.ToLower(path)
	path = strings.Trim(path, "_")
	return path
}
