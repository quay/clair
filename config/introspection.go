package config

import "fmt"

// Trace specifies how to configure Clair's tracing support.
//
// The "Name" key must match the provider to use.
type Trace struct {
	Name        string    `yaml:"name" json:"name"`
	Probability *float64  `yaml:"probability,omitempty" json:"probability,omitempty"`
	Jaeger      Jaeger    `yaml:"jaeger,omitempty" json:"jaeger,omitempty"`
	OTLP        TraceOTLP `yaml:"otlp,omitempty" json:"otlp,omitempty"`
	Sentry      Sentry    `yaml:"sentry,omitempty" json:"sentry,omitempty"`
}

func (t *Trace) lint() ([]Warning, error) {
	switch t.Name {
	case "":
	case "otlp":
	case "sentry":
	case "jaeger":
		return []Warning{{
			path: ".name",
			msg:  `trace provider "jaeger" is deprecated; migrate to "otlp"`,
		}}, nil
	default:
		return []Warning{{
			path: ".name",
			msg:  fmt.Sprintf(`unrecognized trace provider: %q`, t.Name),
		}}, nil
	}
	return nil, nil
}

// Jaeger specific distributed tracing configuration.
//
// Deprecated: The Jaeger project recommends using their OTLP ingestion support
// and the OpenTelemetry exporter for Jaeger has since been removed. Users
// should migrate to OTLP. Clair may refuse to start when configured to emit
// Jaeger traces.
type Jaeger struct {
	Tags  map[string]string `yaml:"tags,omitempty" json:"tags,omitempty"`
	Agent struct {
		Endpoint string `yaml:"endpoint" json:"endpoint"`
	} `yaml:"agent,omitempty" json:"agent,omitempty"`
	Collector struct {
		Username *string `yaml:"username,omitempty" json:"username,omitempty"`
		Password *string `yaml:"password,omitempty" json:"password,omitempty"`
		Endpoint string  `yaml:"endpoint" json:"endpoint"`
	} `yaml:"collector,omitempty" json:"collector,omitempty"`
	ServiceName string `yaml:"service_name,omitempty" json:"service_name,omitempty"`
	BufferMax   int    `yaml:"buffer_max,omitempty" json:"buffer_max,omitempty"`
}

// Sentry is the [Sentry] specific tracing configuration.
//
// [Sentry]: https://sentry.io
type Sentry struct {
	// DSN to be passed to [github.com/getsentry/sentry-go.ClientOptions.Dsn].
	DSN string `yaml:"dsn" json:"dsn"`
	// Environment to be passed to
	// [github.com/getsentry/sentry-go.ClientOptions.Environment].
	Environment string `yaml:"environment,omitempty" json:"environment,omitempty"`
}

// Metrics specifies how to configure Clair's metrics exporting.
//
// The "Name" key must match the provider to use.
type Metrics struct {
	Name       string     `yaml:"name" json:"name"`
	Prometheus Prometheus `yaml:"prometheus,omitempty" json:"prometheus,omitempty"`
	OTLP       MetricOTLP `yaml:"otlp,omitempty" json:"otlp,omitempty"`
}

func (m *Metrics) lint() ([]Warning, error) {
	switch m.Name {
	case "":
	case "otlp":
		return []Warning{{
			path: ".name",
			msg:  `please consult the documentation for the status of metrics via "otlp"`,
		}}, nil
	case "prometheus":
	default:
		return []Warning{{
			path: ".name",
			msg:  fmt.Sprintf(`unrecognized metrics provider: %q`, m.Name),
		}}, nil
	}
	return nil, nil
}

// Prometheus specific metrics configuration.
type Prometheus struct {
	// Endpoint is a URL path where Prometheus metrics will be hosted.
	Endpoint *string `yaml:"endpoint,omitempty" json:"endpoint,omitempty"`
}
