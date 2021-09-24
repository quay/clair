package config

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
)

type TLS struct {
	// The filesystem path where a root CA can be read.
	//
	// This can also be controlled by the SSL_CERT_FILE and SSL_CERT_DIR
	// environment variables, or adding the relevant certs to the system trust
	// store.
	RootCA string `yaml:"root_ca" json:"root_ca"`
	// The filesystem path where a tls certificate can be read.
	Cert string `yaml:"cert" json:"cert"`
	// The filesystem path where a tls private key can be read.
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

	if t.Cert == "" || t.Key == "" {
		return nil, errors.New("both tls cert and key are required")
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

	return &cfg, nil
}
