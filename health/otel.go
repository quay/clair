package health

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/quay/zlog"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/instrumentation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// HealthUnit is the unit that float64 gauges must use to be hooked into this this package's reporting.
//
// The instruments should be implemented as callbacks to avoid missing data after a cold start.
//
// Individual instruments may assign meaning to nonzero values, but should assume the values will
// not be machine parsed.
const HealthUnit = "{health}"

// FallibleKey is an [attribute.Key] that instruments can use as a boolean [attribute.KeyValue] to
// indicate that a metric shouldn't fail the check.
// Requests can override this by using the "strict" query parameter.
//
// Package authors can use this to indicate that there may be something wrong in a downstream service.
// Tripping a process' health check in the event of a transient event may cause restart storms
// or needless load balancer evictions, causing even worse service degradation.
var FallibleKey = attribute.Key("github.com/quay/clair/v4/health.fallible")

// This is modeled on the prometheus exporter: https://github.com/open-telemetry/opentelemetry-go/blob/exporters/prometheus/v0.45.2/exporters/prometheus/exporter.go

// NewMetricsHook returns an [sdkmetric.Reader] for hooking into the otel
// metrics pipeline and an [http.Handler] for serving the health check HTTP API.
//
// The returned [http.Handler] currently does not care about the request path, but may in the
// future. Users should remove any prefixes for forward compatibility.
//
// Three query parameters are used:
//
//   - meter: Select a single meter name.
//   - instrument: Select a single instrument name.
//   - strict: Disregard the "fallible" attribute.
//
// GET and HEAD methods are supported and return the same status code.
// Returned status codes are:
//
//   - 200 OK: All checks reported ok (modified by the "strict" parameter).
//   - 204 No Content: No health check instruments match the supplied filters.
//   - 425 Too Early: Instruments exist, but have no data.
//   - 503 Service Unavailable: At least one check reported not-ok (modified by the "strict" parameter).
//
// GET requests return a body containing details.
// The contents are intended for humans and not considered API.
// The current format is space-separated columns containing:
//
//   - Instrument name
//   - Status
//   - Value
//   - Timestamp
//   - Description
func NewMetricsHook() (sdkmetric.Reader, http.Handler) {
	reader := sdkmetric.NewManualReader()
	c := collector{
		reader: reader,
	}
	return reader, &c
}

// Collector implements the HTTP API by calling the enclosed ManualReader on demand.
//
// There's no provision to prevent a user from DoS-ing the process by making requests in a tight loop.
type collector struct {
	reader  *sdkmetric.ManualReader
	bufPool sync.Pool
}

// ServeHTTP implements [http.Handler].
//
// The API is described in the [NewMetricsHook] documentation.
func (c *collector) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	nowrite := r.Method == http.MethodHead
	switch r.Method {
	case http.MethodGet, http.MethodHead:
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	ctx := r.Context()
	if err := r.ParseForm(); err != nil {
		zlog.Warn(ctx).
			Err(err).
			Msg("unable to parse health check request")
		return
	}
	meter := r.Form.Get(`meter`)
	instrument := r.Form.Get(`instrument`)
	strict := r.Form.Has(`strict`)

	var rm metricdata.ResourceMetrics
	if err := c.reader.Collect(ctx, &rm); err != nil {
		zlog.Warn(ctx).
			Err(err).
			Msg("unable to collect health check")
		return
	}

	// Metric writing hook: by default, do nothing.
	writeMetric := func(s instrumentation.Scope, m metricdata.Metrics, pt metricdata.DataPoint[float64]) {}
	if !nowrite {
		buf := c.getBuf()
		tw := tabwriter.NewWriter(buf, 4, 4, 1, ' ', 0)
		// The actual writing is handled in this defer.
		defer func() {
			tw.Flush()
			io.Copy(w, buf)
			c.putBuf(buf)
			http.NewResponseController(w).Flush()
		}()
		writeMetric = func(s instrumentation.Scope, m metricdata.Metrics, pt metricdata.DataPoint[float64]) {
			fmt.Fprintf(tw, "%s.%s\t%s\t%g\t%s\t# %s\n",
				s.Name, m.Name,
				checkStatus(pt.Value).String(),
				pt.Value,
				pt.Time.UTC().Format(time.RFC3339),
				m.Description,
			)
		}
	}
	status := http.StatusOK
	var haveData bool

Metrics:
	for _, sm := range rm.ScopeMetrics {
		// Tempting to break out of this loop when not writing a body, but we want to return the
		// same status code no matter what. Consider a case where the first instrument has no data
		// and the last one is failing.

		s := sm.Scope
		// Filter if needed.
		if meter != "" && meter != s.Name {
			continue
		}

		for _, m := range sm.Metrics {
			if m.Unit != HealthUnit {
				continue
			}
			g, ok := m.Data.(metricdata.Gauge[float64])
			if !ok {
				continue
			}
			// Filter if needed.
			if instrument != "" && instrument != m.Name {
				continue
			}

			if len(g.DataPoints) == 0 {
				if status < http.StatusTooEarly {
					status = http.StatusTooEarly
				}
				w.Header().Add(`health-data-missing`, s.Name+"."+m.Name)
				continue
			}

			for _, pt := range g.DataPoints {
				haveData = true

				var fallible bool
				if fv, ok := pt.Attributes.Value(FallibleKey); ok && fv.Type() == attribute.BOOL {
					fallible = fv.AsBool()
				}
				switch ok := pt.Value == 0; {
				case ok:
				case fallible && !strict:
				default:
					status = http.StatusServiceUnavailable
				}

				writeMetric(s, m, pt)
			}
		}

		if meter != "" {
			break Metrics
		}
	}
	if !haveData {
		status = http.StatusNoContent
	}

	h := w.Header()
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set("Cache-Control", "max-age=0, must-revalidate, no-cache, no-store, private")
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
}

// CheckStatus formats a float64 for printing.
type checkStatus float64

// String implements [fmt.Stringer].
func (s checkStatus) String() string {
	if s == 0 {
		return " ok"
	}
	return "bad"
}

// GetBuf returns a pooled buffer or creates one.
func (c *collector) getBuf() *bytes.Buffer {
	v := c.bufPool.Get()
	if v == nil {
		var buf bytes.Buffer
		buf.Grow(1024)
		return &buf
	}
	return v.(*bytes.Buffer)
}

// PutBuf resets the buffer and returns it to the pool.
func (c *collector) putBuf(buf *bytes.Buffer) {
	// If gigantic, leak the buffer.
	// Trick from log/slog to reduce steady-state memory usage.
	if buf.Cap() > 4096 {
		return
	}
	buf.Reset()
	c.bufPool.Put(buf)
}
