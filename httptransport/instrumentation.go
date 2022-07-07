package httptransport

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

const (
	metricNamespace = `clair`
	metricSubsystem = `http`
)

type wrapper struct {
	RequestCount    *prometheus.CounterVec
	RequestSize     *prometheus.HistogramVec
	ResponseSize    *prometheus.HistogramVec
	RequestDuration *prometheus.HistogramVec
	InFlight        *prometheus.GaugeVec
}

func (m *wrapper) init(name string) {
	if m.RequestCount == nil {
		m.RequestCount = prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: metricNamespace,
				Subsystem: metricSubsystem,
				Name:      name + "_request_total",
				Help:      "A total count of http requests for the given path",
			},
			[]string{"handler", "code", "method"},
		)
	}
	if m.RequestSize == nil {
		m.RequestSize = prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: metricNamespace,
				Subsystem: metricSubsystem,
				Name:      name + "_request_size_bytes",
				Help:      "Distribution of request sizes for the given path",
			},
			[]string{"handler", "code", "method"},
		)
	}
	if m.ResponseSize == nil {
		m.ResponseSize = prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: metricNamespace,
				Subsystem: metricSubsystem,
				Name:      name + "_response_size_bytes",
				Help:      "Distribution of response sizes for the given path",
			}, []string{"handler", "code", "method"},
		)
	}
	if m.RequestDuration == nil {
		m.RequestDuration = prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: metricNamespace,
				Subsystem: metricSubsystem,
				Name:      name + "_request_duration_seconds",
				Help:      "Distribution of request durations for the given path",
				// These are roughly exponential from 0.5 to 300 seconds
				Buckets: []float64{0.5, 0.7, 1.1, 1.7, 2.7, 4.2, 6.5, 10, 15, 23, 36, 54, 83, 128, 196, 300},
			}, []string{"handler", "code", "method"},
		)
	}
	if m.InFlight == nil {
		m.InFlight = prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: metricNamespace,
				Subsystem: metricSubsystem,
				Name:      name + "_in_flight_requests",
				Help:      "Gauge of requests in flight",
			},
			[]string{"handler"},
		)
	}
	prometheus.MustRegister(m.RequestCount, m.RequestSize, m.ResponseSize, m.RequestDuration, m.InFlight)
}

func (m *wrapper) wrap(tag string, h http.Handler) http.Handler {
	// Add the route tag for traces
	return otelhttp.WithRouteTag(tag,
		// Stack all these metrics handlers.
		promhttp.InstrumentHandlerCounter(m.RequestCount.MustCurryWith(prometheus.Labels{"handler": tag}),
			promhttp.InstrumentHandlerRequestSize(m.RequestSize.MustCurryWith(prometheus.Labels{"handler": tag}),
				promhttp.InstrumentHandlerResponseSize(m.ResponseSize.MustCurryWith(prometheus.Labels{"handler": tag}),
					promhttp.InstrumentHandlerDuration(m.RequestDuration.MustCurryWith(prometheus.Labels{"handler": tag}),
						promhttp.InstrumentHandlerInFlight(m.InFlight.WithLabelValues(tag),
							h))))))
}

func (m *wrapper) wrapFunc(tag string, h http.HandlerFunc) http.Handler {
	return m.wrap(tag, h)
}
