package config

import (
	"fmt"
	"path"
	"strings"
)

// OTLPCommon is common configuration options for an OTLP client.
type OTLPCommon struct {
	// Compression configures payload compression.
	//
	// Only "gzip" is guaranteed to exist for both HTTP and gRPC.
	Compression OTLPCompressor `yaml:"compression,omitempty" json:"compression,omitempty"`
	// Endpoint is the host and port pair that the client should connect to.
	// This is not a URL and must not have a scheme or trailing slashes.
	//
	// The default is "localhost:4317" for gRPC and "localhost:4318" for HTTP.
	Endpoint string `yaml:"endpoint,omitempty" json:"endpoint,omitempty"`
	// Headers adds additional headers to requests.
	Headers map[string]string `yaml:"headers,omitempty" json:"headers,omitempty"`
	// Insecure allows using an unsecured connection to the collector.
	//
	// For gRPC, this means certificate validation is not done.
	// For HTTP, this means HTTP is used instead of HTTPS.
	Insecure bool `yaml:"insecure,omitempty" json:"insecure,omitempty"`
	// Timeout is the maximum amount of time for a submission.
	//
	// The default is 10 seconds.
	Timeout *Duration `yaml:"timeout,omitempty" json:"timeout,omitempty"`
	// ClientTLS configures client TLS certificates, meaning a user should
	// ignore the "RootCA" member and look only at the "Cert" and "Key" members.
	//
	// See the documentation for the TLS struct for recommendations on
	// configuring certificate authorities.
	ClientTLS *TLS `yaml:"client_tls,omitempty" json:"client_tls,omitempty"`
}

// Lint implements [linter].
func (c *OTLPCommon) lint() (ws []Warning, _ error) {
	if c.Timeout != nil && *c.Timeout == 0 {
		ws = append(ws, Warning{
			path: ".timeout",
			msg:  "timeout of 0 is almost certainly wrong",
		})
	}
	return ws, nil
}

// Validate implements [validator].
func (c *OTLPCommon) validate(_ Mode) (ws []Warning, _ error) {
	return c.lint()
}

// OTLPHTTPCommon is common configuration options for an OTLP HTTP client.
type OTLPHTTPCommon struct {
	OTLPCommon
	// URLPath overrides the URL path for sending traces. If unset, the default
	// is "/v1/traces".
	URLPath string `yaml:"url_path,omitempty" json:"url_path,omitempty"`
}

// Lint implements [linter].
func (c *OTLPHTTPCommon) lint() (ws []Warning, _ error) {
	if c.URLPath != "" && strings.HasSuffix(c.URLPath, "/") {
		ws = append(ws, Warning{
			path: ".URLPath",
			msg:  fmt.Sprintf("path %q has a trailing slash; this is probably incorrect", c.URLPath),
		})
	}
	return ws, nil
}

// Validate implements [validator].
func (c *OTLPHTTPCommon) validate(_ Mode) (ws []Warning, err error) {
	ws, err = c.lint()
	if err != nil {
		return ws, err
	}
	if c.URLPath != "" {
		c.URLPath = path.Clean(c.URLPath)
		if !path.IsAbs(c.URLPath) {
			return ws, &Warning{
				path: ".URLPath",
				msg:  fmt.Sprintf("path %q must be absolute", c.URLPath),
			}
		}
	}
	return ws, nil
}

// OTLPgRPCCommon is common configuration options for an OTLP gRPC client.
type OTLPgRPCCommon struct {
	OTLPCommon
	// Reconnect sets the minimum amount of time between connection attempts.
	Reconnect *Duration `yaml:"reconnect,omitempty" json:"reconnect,omitempty"`
	// ServiceConfig specifies a gRPC service config as a string containing JSON.
	// See the [doc] for the format and possibilities.
	//
	// [doc]: https://github.com/grpc/grpc/blob/master/doc/service_config.md
	ServiceConfig string `yaml:"service_config,omitempty" json:"service_config,omitempty"`
}

// TraceOTLP is the configuration for an OTLP traces client.
//
// See the [OpenTelemetry docs] for more information on traces.
// See the Clair docs for the current status of of the instrumentation.
//
// [OpenTelemetry docs]: https://opentelemetry.io/docs/concepts/signals/traces/
type TraceOTLP struct {
	// HTTP configures OTLP via HTTP.
	HTTP *TraceOTLPHTTP `yaml:"http,omitempty" json:"http,omitempty"`
	// GRPC configures OTLP via gRPC.
	GRPC *TraceOTLPgRPC `yaml:"grpc,omitempty" json:"grpc,omitempty"`
}

// Lint implements [linter].
func (t *TraceOTLP) lint() (ws []Warning, _ error) {
	if t.HTTP != nil && t.GRPC != nil {
		ws = append(ws, Warning{
			msg: `both "http" and "grpc" are configured, this may cause duplicate submissions`,
		})
	}
	return ws, nil
}

// TraceOTLPHTTP is the configuration for an OTLP traces HTTP client.
type TraceOTLPHTTP struct {
	OTLPHTTPCommon
}

// TraceOTLPgRPC is the configuration for an OTLP traces gRPC client.
type TraceOTLPgRPC struct {
	OTLPgRPCCommon
}

// MetricOTLP is the configuration for an OTLP metrics client.
//
// See the [OpenTelemetry docs] for more information on metrics.
// See the Clair docs for the current status of of the instrumentation.
//
// [OpenTelemetry docs]: https://opentelemetry.io/docs/concepts/signals/metrics/
type MetricOTLP struct {
	// HTTP configures OTLP via HTTP.
	HTTP *MetricOTLPHTTP `yaml:"http,omitempty" json:"http,omitempty"`
	// GRPC configures OTLP via gRPC.
	GRPC *MetricOTLPgRPC `yaml:"grpc,omitempty" json:"grpc,omitempty"`
}

// Lint implements [linter].
func (m *MetricOTLP) lint() (ws []Warning, _ error) {
	if m.HTTP != nil && m.GRPC != nil {
		ws = append(ws, Warning{
			msg: `both "http" and "grpc" are configured, this may cause duplicate submissions`,
		})
	}
	return ws, nil
}

// MetricOTLPHTTP is the configuration for an OTLP metrics HTTP client.
type MetricOTLPHTTP struct {
	OTLPHTTPCommon
}

// MetricOTLPgRPC is the configuration for an OTLP metrics gRPC client.
type MetricOTLPgRPC struct {
	OTLPgRPCCommon
}

//go:generate go run golang.org/x/tools/cmd/stringer@latest -type OTLPCompressor -linecomment

// OTLPCompressor is the valid options for compressing OTLP payloads.
type OTLPCompressor int

// OTLPCompressor values
const (
	OTLPCompressUnset OTLPCompressor = iota //
	OTLPCompressNone                        // none
	OTLPCompressGzip                        // gzip
)
