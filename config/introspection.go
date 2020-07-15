package config

type Trace struct {
	Name        string   `yaml:"name" json:"name"`
	Probability *float64 `yaml:"probability" json:"probability"`
	Jaeger      Jaeger   `yaml:"jaeger" json:"jaeger"`
}

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

type Metrics struct {
	Name       string     `yaml:"name" json:"name"`
	Prometheus Prometheus `yaml:"prometheus" json:"prometheus"`
	Dogstatsd  Dogstatsd  `yaml:"dogstatsd" json:"dogstatsd"`
}

type Prometheus struct {
	Endpoint *string `yaml:"endpoint" json:"endpoint"`
}

type Dogstatsd struct {
	URL string `yaml:"url" json:"url"`
}
