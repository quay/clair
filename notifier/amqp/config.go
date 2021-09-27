package amqp

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/quay/clair/v4/config"
)

// Exchange are the required fields necessary to check the existence of an
// Exchange.
//
// For more details see: https://godoc.org/github.com/streadway/amqp#Channel.ExchangeDeclarePassive
type exchange struct {
	// The name of the exchange
	Name string
	// The type of the exchange. Typically:
	// "direct"
	// "fanout"
	// "topic"
	// "headers"
	Type string
	// Whether the exchange survives server restarts
	Durable bool
	// Whether bound consumers define the lifecycle of the Exchange.
	AutoDelete bool
}

func loadTLSConfig(c *config.AMQP) (*tls.Config, error) {
	var cfg tls.Config
	usingTLS := false
	for _, u := range c.URIs {
		if strings.HasPrefix(u, "amqps://") {
			usingTLS = true
			break
		}
	}
	if !usingTLS {
		return &cfg, nil
	}

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

func exchangeFrom(c *config.AMQP) exchange {
	return exchange{
		Name:       c.Exchange.Name,
		Type:       c.Exchange.Type,
		Durable:    c.Exchange.Durable,
		AutoDelete: c.Exchange.AutoDelete,
	}
}
