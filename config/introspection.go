package config

// Configure distributed tracing via OTEL
type Trace struct {
	Name        string   `yaml:"name" json:"name"`
	Probability *float64 `yaml:"probability" json:"probability"`
	Jaeger      Jaeger   `yaml:"jaeger" json:"jaeger"`
}

// Jager specific distributed tracing configuration.
type Jaeger struct {
	Agent struct {
		Endpoint string `yaml:"endpoint" json:"endpoint"`
	} `yaml:"agent" json:"agent"`
	Collector struct {
		Endpoint string  `yaml:"endpoint" json:"endpoint"`
		Username *string `yaml:"username" json:"username"`
		Password *string `yaml:"password" json:"password"`
	} `yaml:"collector" json:"collector"`
	ServiceName string            `yaml:"service_name" json:"service_name"`
	Tags        map[string]string `yaml:"tags" json:"tags"`
	BufferMax   int               `yaml:"buffer_max" json:"buffer_max"`
}

// Configure Metrics.
type Metrics struct {
	Name       string     `yaml:"name" json:"name"`
	Prometheus Prometheus `yaml:"prometheus" json:"prometheus"`
}

// Prometheus specific metrics configuration
type Prometheus struct {
	// Endpoint is a URL path where
	// Prometheus metrics will be hosted.
	Endpoint *string `yaml:"endpoint" json:"endpoint"`
}
