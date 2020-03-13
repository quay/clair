package introspection

import (
	"net/http"
	"time"

	"go.opentelemetry.io/otel/api/global"
	"go.opentelemetry.io/otel/api/key"
	"go.opentelemetry.io/otel/api/metric"
	"go.opentelemetry.io/otel/api/unit"
)

var pathKey = key.New("http.path")

// Handler wraps the provided http.Handler and provides
// latency recordings per incoming http path using the
// open telemetry library
func Handler(next http.Handler) http.Handler {
	meter := global.MeterProvider().Meter("clair")
	late := meter.NewInt64Measure("clair.http.latency",
		metric.WithDescription("latency of http requests"),
		metric.WithUnit(unit.Milliseconds),
		metric.WithAbsolute(true),
		metric.WithKeys(pathKey),
	)
	h := &handler{
		meter:   meter,
		latency: late,
		next:    next,
	}

	return h
}

// handler implements the http.Handler interface
type handler struct {
	meter   metric.Meter
	latency metric.Int64Measure
	next    http.Handler
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	labels := h.meter.Labels(pathKey.String(r.URL.Path))
	start := time.Now()
	h.next.ServeHTTP(w, r)
	h.latency.Record(ctx, time.Now().Sub(start).Milliseconds(), labels)
}
