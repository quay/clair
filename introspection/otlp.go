package introspection

import (
	"crypto/tls"
	"fmt"
	"time"

	"github.com/quay/clair/config"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"google.golang.org/grpc/credentials"
)

// This file holds all the OTLP weirdness.
//
// Most of the options are the same internally, but have a bunch of type ceremony around them to obfuscate this.

// OtlpHooks is a hook structure for using the correct types with the various OTLP exporters.
// The declared variables are largely duplicates, with the real logic living in [otlpHooks.Options].
//
// The type parameter "O" should really be a sum type, but that's currently inexpressible.
type otlpHooks[O any] struct {
	WithCompressor      func(config.OTLPCompressor) O
	WithEndpoint        func(string) O
	WithHeaders         func(map[string]string) O
	WithInsecure        func() O
	WithTimeout         func(time.Duration) O
	WithTLSClientConfig func(*tls.Config) O

	WithURLPath func(string) O

	WithReconnectionPeriod func(time.Duration) O
	WithServiceConfig      func(string) O
}

// Options returns the correct Options to pass into the constructor based on the receiver type.
//
// This function will panic if called in unexpected ways. To be safe:
//
//   - Only use the provided instances ([omhHooks], [omgHooks], [othHooks], [otgHooks]).
//   - Read the implementation.
func (h *otlpHooks[O]) Options(v any) (opts []O, err error) {
	switch cfg := v.(type) {
	// Signal-specific options.
	//
	// Currently, none; recurse to the transport options.
	case *config.MetricOTLPHTTP:
		opts, err = h.Options(&cfg.OTLPHTTPCommon)
	case *config.TraceOTLPHTTP:
		opts, err = h.Options(&cfg.OTLPHTTPCommon)
	case *config.MetricOTLPgRPC:
		opts, err = h.Options(&cfg.OTLPgRPCCommon)
	case *config.TraceOTLPgRPC:
		opts, err = h.Options(&cfg.OTLPgRPCCommon)

	// Transport-specific options.
	//
	// Recurse to the common options then return the transport options, in case of some ordering oddness.
	// Will panic if called on the wrong receiver, as some of the members will (purposefully!) be nil.
	case *config.OTLPHTTPCommon:
		opts, err = h.Options(&cfg.OTLPCommon)
		if err != nil {
			return nil, err
		}
		if p := cfg.URLPath; p != "" {
			opts = append(opts, h.WithURLPath(p))
		}
	case *config.OTLPgRPCCommon:
		opts, err = h.Options(&cfg.OTLPCommon)
		if err != nil {
			return nil, err
		}
		if r := cfg.Reconnect; r != nil {
			opts = append(opts, h.WithReconnectionPeriod(time.Duration(*r)))
		}
		if srv := cfg.ServiceConfig; srv != "" {
			opts = append(opts, h.WithServiceConfig(srv))
		}

	// Common options.
	case *config.OTLPCommon:
		if e := cfg.Endpoint; e != "" {
			opts = append(opts, h.WithEndpoint(e))
		}
		opts = append(opts, h.WithCompressor(cfg.Compression))
		if len(cfg.Headers) != 0 {
			opts = append(opts, h.WithHeaders(cfg.Headers))
		}
		if cfg.Insecure {
			opts = append(opts, h.WithInsecure())
		}
		if t := cfg.Timeout; t != nil {
			opts = append(opts, h.WithTimeout(time.Duration(*t)))
		}
		if tc := cfg.ClientTLS; tc != nil {
			tlscfg, err := tc.Config()
			if err != nil {
				return nil, fmt.Errorf("TLS client configuration error: %w", err)
			}
			opts = append(opts, h.WithTLSClientConfig(tlscfg))
		}

	// Make the switch exhaustive.
	default:
		panic(fmt.Sprintf("programmer error: unexpected type: %T", v))
	}
	return opts, nil
}

// In order, these instances are for:
//
//   - Metrics HTTP
//   - Metrics gRPC
//   - Traces HTTP
//   - Traces gRPC
var (
	omhHooks = otlpHooks[otlpmetrichttp.Option]{
		WithCompressor: otlpCompressorHook(
			otlpmetrichttp.WithCompression(otlpmetrichttp.NoCompression),
			otlpmetrichttp.WithCompression(otlpmetrichttp.GzipCompression),
		),
		WithEndpoint:        otlpmetrichttp.WithEndpoint,
		WithHeaders:         otlpmetrichttp.WithHeaders,
		WithInsecure:        otlpmetrichttp.WithInsecure,
		WithTimeout:         otlpmetrichttp.WithTimeout,
		WithTLSClientConfig: otlpmetrichttp.WithTLSClientConfig,
		WithURLPath:         otlpmetrichttp.WithURLPath,
	}
	omgHooks = otlpHooks[otlpmetricgrpc.Option]{
		WithCompressor: otlpCompressorHook(
			otlpmetricgrpc.WithCompressor("none"),
			otlpmetricgrpc.WithCompressor("gzip"),
		),
		WithEndpoint:           otlpmetricgrpc.WithEndpoint,
		WithHeaders:            otlpmetricgrpc.WithHeaders,
		WithInsecure:           otlpmetricgrpc.WithInsecure,
		WithTimeout:            otlpmetricgrpc.WithTimeout,
		WithTLSClientConfig:    grpcTLSHook(otlpmetricgrpc.WithTLSCredentials),
		WithReconnectionPeriod: otlpmetricgrpc.WithReconnectionPeriod,
		WithServiceConfig:      otlpmetricgrpc.WithServiceConfig,
	}
	othHooks = otlpHooks[otlptracehttp.Option]{
		WithCompressor: otlpCompressorHook(
			otlptracehttp.WithCompression(otlptracehttp.NoCompression),
			otlptracehttp.WithCompression(otlptracehttp.GzipCompression),
		),
		WithEndpoint:        otlptracehttp.WithEndpoint,
		WithHeaders:         otlptracehttp.WithHeaders,
		WithInsecure:        otlptracehttp.WithInsecure,
		WithTimeout:         otlptracehttp.WithTimeout,
		WithTLSClientConfig: otlptracehttp.WithTLSClientConfig,
		WithURLPath:         otlptracehttp.WithURLPath,
	}
	otgHooks = otlpHooks[otlptracegrpc.Option]{
		WithCompressor: otlpCompressorHook(
			otlptracegrpc.WithCompressor("none"),
			otlptracegrpc.WithCompressor("gzip"),
		),
		WithEndpoint:           otlptracegrpc.WithEndpoint,
		WithHeaders:            otlptracegrpc.WithHeaders,
		WithInsecure:           otlptracegrpc.WithInsecure,
		WithTimeout:            otlptracegrpc.WithTimeout,
		WithTLSClientConfig:    grpcTLSHook(otlptracegrpc.WithTLSCredentials),
		WithReconnectionPeriod: otlptracegrpc.WithReconnectionPeriod,
		WithServiceConfig:      otlptracegrpc.WithServiceConfig,
	}
)

// OtlpCompressorHook maps from the [config.OTLPCompressor] type to the correct option.
//
// The type parameter is too broad, see also [otlpHooks].
// This function causes some extra garbage to be created.
// Inlining and simplifying at use sites would prevent the options from being constructed until needed,
// but consolidates the precedence and default logic.
func otlpCompressorHook[O any](none, gzip O) func(config.OTLPCompressor) O {
	return func(z config.OTLPCompressor) O {
		switch z {
		case config.OTLPCompressUnset: // Actual default:
			fallthrough
		case config.OTLPCompressNone:
			return none
		case config.OTLPCompressGzip:
			return gzip
		default:
			panic("unreachable: exhaustive switch")
		}
	}
}

// GrpcTLSHook maps a [tls.Config] to a correctly typed option.
//
// The type parameter is too broad, see also [otlpHooks].
func grpcTLSHook[O any](f func(credentials.TransportCredentials) O) func(*tls.Config) O {
	return func(c *tls.Config) O { return f(credentials.NewTLS(c)) }
}
