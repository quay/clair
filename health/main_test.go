package health

import (
	"os"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/sdk/metric"
)

func TestMain(m *testing.M) {
	exit := 0
	defer func() {
		if exit != 0 {
			os.Exit(exit)
		}
	}()

	exp, h := NewMetricsHook()
	handler = h // Declared in otel_test.go
	p := metric.NewMeterProvider(metric.WithReader(exp))
	otel.SetMeterProvider(p)

	exit = m.Run()
}
