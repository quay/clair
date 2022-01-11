package httptransport

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

type wrapper struct {
	RequestCount    *prometheus.CounterVec
	RequestSize     *prometheus.HistogramVec
	ResponseSize    *prometheus.HistogramVec
	RequestDuration *prometheus.HistogramVec
	InFlight        *prometheus.GaugeVec
}

func (m *wrapper) init() {
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
