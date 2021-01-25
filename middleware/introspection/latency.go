package introspection

import (
	"net/http"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/label"
	"go.opentelemetry.io/otel/metric"
)

// Handler wraps the provided http.Handler and provides
// latency recordings per incoming http path using the
// open telemetry library
//
// The passed in pattern will be used as a metric key along
// with the http request method.
// For example a resulting prometheus latency metric will take the form
// "clair_http_latence{http_path={path}, http.method={method}}"
func Handler(next http.Handler, path string) http.Handler {
	meter := otel.Meter("clair")
	latency := metric.Must(meter).NewInt64UpDownCounter(
		// for some reason, the namespace of "clair" is not applied
		// to the metric when it lands in prometheus, so add it to the name anyway
		// same goes with the WithUnit option.
		"clair_http_latency_ms",
		metric.WithDescription("latency of http request"),
	)
	h := &handler{
		meter:   meter,
		latency: latency,
		pathKV:  label.String("http_path", path),
		next:    next,
	}

	return h
}

// handler implements the http.Handler interface
type handler struct {
	// an instance to the ot metrics provider
	meter metric.Meter
	// the metric we will instrument http latency with
	latency metric.Int64UpDownCounter
	// an ot KV which represents the handler path this middleware is wrapping
	pathKV label.KeyValue
	// the next handler to call in the chain
	next http.Handler
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	start := time.Now()
	h.next.ServeHTTP(w, r)
	h.latency.Add(ctx, int64(time.Now().Sub(start).Milliseconds()), h.pathKV, methodKV(r))
}
