package config

import "fmt"

// Trace specifies how to configure Clair's tracing support.
//
// The "Name" key must match the provider to use.
//
// Currently, only "jaeger" is supported.
type Trace struct {
	Name        string   `yaml:"name" json:"name"`
	Probability *float64 `yaml:"probability" json:"probability"`
	Jaeger      Jaeger   `yaml:"jaeger" json:"jaeger"`
}

func (t *Trace) lint() ([]Warning, error) {
	switch t.Name {
	case "":
	case "jaeger":
	default:
		return []Warning{{
			path: ".name",
			msg:  fmt.Sprintf(`unrecognized trace provider: %q`, t.Name),
		}}, nil
	}
	return nil, nil
}

// Jaeger specific distributed tracing configuration.
type Jaeger struct {
	Tags  map[string]string `yaml:"tags" json:"tags"`
	Agent struct {
		Endpoint string `yaml:"endpoint" json:"endpoint"`
	} `yaml:"agent" json:"agent"`
	Collector struct {
		Username *string `yaml:"username" json:"username"`
		Password *string `yaml:"password" json:"password"`
		Endpoint string  `yaml:"endpoint" json:"endpoint"`
	} `yaml:"collector" json:"collector"`
	ServiceName string `yaml:"service_name" json:"service_name"`
	BufferMax   int    `yaml:"buffer_max" json:"buffer_max"`
}

// Metrics specifies how to configure Clair's metrics exporting.
//
// The "Name" key must match the provider to use.
//
// Currently, only "prometheus" is supported.
type Metrics struct {
	Prometheus Prometheus `yaml:"prometheus" json:"prometheus"`
	Name       string     `yaml:"name" json:"name"`
}

func (m *Metrics) lint() ([]Warning, error) {
	switch m.Name {
	case "":
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
	// Endpoint is a URL path where
	// Prometheus metrics will be hosted.
	Endpoint *string `yaml:"endpoint" json:"endpoint"`
}
