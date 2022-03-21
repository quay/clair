package config

import "fmt"

// Trace specifies how to configure Clair's tracing support.
//
// The "Name" key must match the provider to use.
//
// Currently, only "jaeger" is supported.
type Trace struct {
	Name        string   `yaml:"name" json:"name"`
	Probability *float64 `yaml:"probability,omitempty" json:"probability,omitempty"`
	Jaeger      Jaeger   `yaml:"jaeger,omitempty" json:"jaeger,omitempty"`
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

// Metrics specifies how to configure Clair's metrics exporting.
//
// The "Name" key must match the provider to use.
//
// Currently, only "prometheus" is supported.
type Metrics struct {
	Prometheus Prometheus `yaml:"prometheus,omitempty" json:"prometheus,omitempty"`
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
	// Endpoint is a URL path where Prometheus metrics will be hosted.
	Endpoint *string `yaml:"endpoint,omitempty" json:"endpoint,omitempty"`
}
