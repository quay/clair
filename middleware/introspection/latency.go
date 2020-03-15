package introspection

import (
	"net/http"
	"time"

	"go.opentelemetry.io/otel/api/core"
	"go.opentelemetry.io/otel/api/global"
	"go.opentelemetry.io/otel/api/key"
	"go.opentelemetry.io/otel/api/metric"
	"go.opentelemetry.io/otel/api/unit"
)

// pathKey is the label for the http path a latency
// metric pertains to.
var pathKey = key.New("http.path")

// methodKey is the label accompanying pathKey and
// provides the http method of the requested path
var methodKey = key.New("http.method")

// Handler wraps the provided http.Handler and provides
// latency recordings per incoming http path using the
// open telemetry library
//
// The passed in pattern will be used as a metric key along
// with the http request method.
// For example a resulting prometheus latency metric will take the form
// "clair_http_latence{http_path={path}, http.method={method}}"
func Handler(next http.Handler, path string) http.Handler {
	meter := global.MeterProvider().Meter("clair")
	late := meter.NewInt64Measure("clair.http.latency",
		metric.WithDescription("latency of http requests"),
		metric.WithUnit(unit.Milliseconds),
		metric.WithAbsolute(true),
		metric.WithKeys(pathKey),
		metric.WithKeys(methodKey),
	)
	h := &handler{
		meter:   meter,
		latency: late,
		pathKV:  pathKey.String(path),
		next:    next,
	}

	return h
}

// handler implements the http.Handler interface
type handler struct {
	// an instance to the ot metrics provider
	meter metric.Meter
	// the metric we will instrument http latency with
	latency metric.Int64Measure
	// an ot KV which represents the handler path this middleware is wrapping
	pathKV core.KeyValue
	// the next handler to call in the chain
	next http.Handler
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	start := time.Now()
	h.next.ServeHTTP(w, r)
	h.latency.Record(ctx, time.Now().Sub(start).Milliseconds(), h.meter.Labels(h.pathKV, methodKV(r)))
}
