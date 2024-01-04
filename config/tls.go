package config

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
)

// TLS describes some TLS settings.
//
// Some uses of this type ignore the RootCA member; see the documentation at the
// use site to determine if that's the case.
//
// Using the environment variables "SSL_CERT_DIR" or "SSL_CERT_FILE" or
// modifying the system's trust store are the ways to modify root CAs for all
// outgoing TLS connections.
type TLS struct {
	// The filesystem path where a root CA can be read.
	//
	// This can also be controlled by the SSL_CERT_FILE and SSL_CERT_DIR
	// environment variables, or adding the relevant certs to the system trust
	// store.
	RootCA string `yaml:"root_ca" json:"root_ca"`
	// The filesystem path where a TLS certificate can be read.
	Cert string `yaml:"cert" json:"cert"`
	// The filesystem path where a TLS private key can be read.
	Key string `yaml:"key" json:"key"`
}

// Config returns a tls.Config modified according to the TLS struct.
//
// If the *TLS is nil, a default tls.Config is returned.
func (t *TLS) Config() (*tls.Config, error) {
	var cfg tls.Config
	if t == nil {
		return &cfg, nil
	}

	if t.RootCA != "" {
		p, err := x509.SystemCertPool()
		if err != nil {
			return nil, err
		}
		ca, err := os.ReadFile(t.RootCA)
		if err != nil {
			return nil, fmt.Errorf("failed to read tls root ca: %w", err)
		}
		if !p.AppendCertsFromPEM(ca) {
			return nil, errors.New("unable to add certificate to pool")
		}
		cfg.RootCAs = p
	}

	cert, err := tls.LoadX509KeyPair(t.Cert, t.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to read x509 cert and key pair: %w", err)
	}
	cfg.Certificates = append(cfg.Certificates, cert)
	cfg.MinVersion = tls.VersionTLS12

	return &cfg, nil
}

func (t *TLS) lint() ([]Warning, error) {
	if t.RootCA != "" {
		return []Warning{{
			path:  ".root_ca",
			inner: fmt.Errorf(`use environment variables "SSL_CERT_FILE" or "SSL_CERT_DIR": %w`, ErrDeprecated),
		}}, nil
	}
	return nil, nil
}

func (t *TLS) validate(_ Mode) ([]Warning, error) {
	if (t.Cert != "" || t.Key != "") && (t.Cert == "" || t.Key == "") {
		return nil, errors.New("both tls cert and key are required")
	}
	for _, n := range []string{t.RootCA, t.Cert, t.Key} {
		if n == "" {
			continue
		}
		_, err := os.Stat(n)
		if err != nil {
			return nil, fmt.Errorf(`error accessing %q: %w`, n, err)
		}
	}
	return nil, nil
}
