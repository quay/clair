package stomp

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"

	"github.com/quay/clair/v4/config"
)

func loadTLSConfig(c *config.STOMP) (*tls.Config, error) {
	if c.TLS == nil {
		return nil, nil
	}
	var cfg tls.Config

	if c.TLS.Cert == "" || c.TLS.Key == "" {
		return nil, errors.New("both tls cert and key are required")
	}
	if c.TLS.RootCA != "" {
		if c.TLS.RootCA != "" {
			p, err := x509.SystemCertPool()
			if err != nil {
				return nil, err
			}
			ca, err := os.ReadFile(c.TLS.RootCA)
			if err != nil {
				return nil, fmt.Errorf("failed to read tls root ca: %w", err)
			}
			if !p.AppendCertsFromPEM(ca) {
				return nil, errors.New("unable to add certificate to pool")
			}
			cfg.RootCAs = p
		}
	}

	cert, err := tls.LoadX509KeyPair(c.TLS.Cert, c.TLS.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to read x509 cert and key pair: %w", err)
	}
	cfg.Certificates = append(cfg.Certificates, cert)

	return &cfg, nil
}
