package health

import (
	"bufio"
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"sync/atomic"
	"testing"

	"github.com/quay/zlog"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
)

var (
	status  atomic.Value
	handler http.Handler
)

func init() {
	otel.GetMeterProvider().Meter("github.com/quay/clair/v4/health").Float64ObservableGauge("dummy",
		metric.WithDescription("This is a dummy healthcheck."),
		metric.WithUnit(HealthUnit),
		metric.WithFloat64Callback(func(_ context.Context, o metric.Float64Observer) error {
			o.Observe(status.Load().(float64))
			return nil
		}),
	)
	otel.GetMeterProvider().Meter("example.com/health").Float64ObservableGauge("example",
		metric.WithDescription(`Example of a "fallible" check.`),
		metric.WithUnit(HealthUnit),
		metric.WithFloat64Callback(func(_ context.Context, o metric.Float64Observer) error {
			o.Observe(status.Load().(float64),
				metric.WithAttributes(FallibleKey.Bool(true)))
			return nil
		}),
	)

	var call int64
	otel.GetMeterProvider().Meter("example.com/health").Int64ObservableCounter("other",
		metric.WithDescription("This is a dummy healthcheck that always reports OK."),
		metric.WithUnit("{count}"),
		metric.WithInt64Callback(func(_ context.Context, o metric.Int64Observer) error {
			o.Observe(atomic.AddInt64(&call, 1))
			return nil
		}),
	)
}

func runRequest(t *testing.T, r *http.Request, check func(*testing.T, *http.Response)) {
	t.Helper()
	ctx := zlog.Test(context.Background(), t)
	w := httptest.NewRecorder()
	w.Body = new(bytes.Buffer)

	t.Logf("request URI: %s %s", r.Method, r.URL.RequestURI())
	handler.ServeHTTP(w, r.WithContext(ctx))

	t.Logf("body:\n%s", w.Body.String())
	res := w.Result()
	defer res.Body.Close()
	check(t, res)
}

func checkOKRegexp(pat string) func(*testing.T, *http.Response) {
	re := regexp.MustCompile(pat)
	return func(t *testing.T, res *http.Response) {
		t.Logf("status code: got: %d, want: %d", res.StatusCode, http.StatusOK)
		if got, want := res.StatusCode, http.StatusOK; got != want {
			t.Fail()
		}
		if !re.MatchReader(bufio.NewReader(res.Body)) {
			t.Error("regexp failed")
		}
	}
}

func TestHTTP(t *testing.T) {
	// Setup
	status.Store(float64(0))
	mp := otel.GetMeterProvider()
	meter := mp.Meter("test")
	_, err := meter.Float64ObservableGauge("dummy",
		metric.WithDescription("This is a dummy healthcheck."),
		metric.WithUnit(HealthUnit),
		metric.WithFloat64Callback(func(_ context.Context, o metric.Float64Observer) error {
			o.Observe(status.Load().(float64))
			return nil
		}),
	)
	if err != nil {
		t.Fatal(err)
	}

	// Tests
	// Basic ones:
	t.Run("OK", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		runRequest(t, r, checkOKRegexp(`.`))
	})
	t.Run("HEAD", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodHead, "/", nil)
		runRequest(t, r,
			func(t *testing.T, res *http.Response) {
				t.Logf("status code: got: %d, want: %d", res.StatusCode, http.StatusOK)
				if got, want := res.StatusCode, http.StatusOK; got != want {
					t.Fail()
				}
			})
	})
	t.Run("Single", func(t *testing.T) {
		pkg := "github.com/quay/clair/v4/health"
		r := httptest.NewRequest(http.MethodGet, "/?meter="+url.PathEscape(pkg), nil)
		runRequest(t, r, checkOKRegexp(`^`+pkg+`\.\w+ `)) // not exactly correct, but good enough.
	})

	// With failing checks:
	status.Store(float64(0.5))
	t.Run("Fail", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		runRequest(t, r, func(t *testing.T, res *http.Response) {
			got, want := res.StatusCode, http.StatusServiceUnavailable
			t.Logf("status code: got: %d, want: %d", got, want)
			if got != want {
				t.Fail()
			}
		})
	})
	t.Run("Fallible", func(t *testing.T) {
		v := url.Values{
			"meter": {"example.com/health"},
		}
		t.Run("Lax", func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/?"+v.Encode(), nil)
			runRequest(t, r, checkOKRegexp(`.`))
		})
		t.Run("Strict", func(t *testing.T) {
			v.Set("strict", "")
			r := httptest.NewRequest(http.MethodGet, "/?"+v.Encode(), nil)
			runRequest(t, r, func(t *testing.T, res *http.Response) {
				got, want := res.StatusCode, http.StatusServiceUnavailable
				t.Logf("status code: got: %d, want: %d", got, want)
				if got != want {
					t.Fail()
				}
			})
		})
	})
}
