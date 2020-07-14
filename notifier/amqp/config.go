package amqp

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/url"
	"strings"
)

type TLS struct {
	// The filesystem path where a root CA can be read.
	RootCA string `yaml:"root_ca"`
	// The filesystem path where a tls certificate can be read.
	Cert string `yaml:"cert"`
	// The filesystem path where a tls private key can be read.
	Key string `yaml:"key"`
}

// Exchange are the required fields necessary to check
// the existence of an Exchange
//
// For more details see: https://godoc.org/github.com/streadway/amqp#Channel.ExchangeDeclarePassive
type Exchange struct {
	// The name of the exchange
	Name string `yaml:"name"`
	// The type of the exchange. Typically:
	// "direct"
	// "fanout"
	// "topic"
	// "headers"
	Type string `yaml:"type"`
	// Whether the exchange survives server restarts
	Durable bool `yaml:"durability"`
	// Whether bound consumers define the lifecycle of the Exchange.
	AutoDelete bool `yaml:"auto_delete"`
}

// Config provides configuration for an AMQP deliverer.
type Config struct {
	// Configures the AMQP delivery to deliver notifications directly to
	// the configured Exchange.
	//
	// If true "Callback" is ignored.
	// If false a notifier.Callback is delivered to the queue and clients
	// utilize the pagination API to retrieve.
	Direct bool
	// Specifies the number of notifications delivered in single AMQP message
	// when Direct is true.
	//
	// Ignored if Direct is not true
	// If 0 or 1 is provided no rollup occurs and each notification is delivered
	// separately.
	Rollup int
	// The AMQP exchange notifications will be delivered to.
	// A passive declare is performed and if the exchange does not exist
	// the declare will fail.
	Exchange Exchange `yaml:"exchange"`
	// The routing key used to route notifications to the desired queue.
	RoutingKey string `yaml:"routing_key"`
	// The callback url where notifications are retrieved.
	Callback string
	callback url.URL
	// A list of AMQP compliant URI scheme. see: https://www.rabbitmq.com/uri-spec.html
	// example: "amqp://user:pass@host:10000/vhost"
	//
	// The first successful connection will be used by the amqp deliverer.
	//
	// If "amqps://" broker URI schemas are provided the TLS configuration below is required.
	URIs []string `yaml:"uris"`
	TLS  *TLS     `yaml:"tls"`
	tls  *tls.Config
}

// Validate confirms configuration is valid and fills in private members
// with parsed values on success.
func (c *Config) Validate() (Config, error) {
	conf := *c
	if c.Exchange.Type == "" {
		return conf, fmt.Errorf("AMQP config requires the exchange.type field")
	}
	if c.RoutingKey == "" {
		return conf, fmt.Errorf("AMQP config requires the routing key field")
	}
	for _, uri := range c.URIs {
		if strings.HasPrefix(uri, "amqps://") {
			if c.TLS.RootCA == "" {
				return conf, fmt.Errorf("amqps:// broker requires tls_root_ca")
			}
			if c.TLS.Cert == "" {
				return conf, fmt.Errorf("amqps:// broker requires tls_cert")
			}
			if c.TLS.Key == "" {
				return conf, fmt.Errorf("amqps:// broker requires tls_key")
			}
		}
	}

	if c.TLS != nil {
		if c.TLS.Cert == "" || c.TLS.Key == "" {
			return conf, fmt.Errorf("both tls cert and key are required")
		}
		TLS := tls.Config{}
		if pool, err := x509.SystemCertPool(); err != nil {
			TLS.RootCAs = x509.NewCertPool()
		} else {
			TLS.RootCAs = pool
		}

		if c.TLS.RootCA != "" {
			var err error
			ca := []byte{}
			if ca, err = ioutil.ReadFile(c.TLS.RootCA); err != nil {
				return conf, fmt.Errorf("failed to read tls root ca: %v", err)
			}
			TLS.RootCAs.AppendCertsFromPEM(ca)
		}

		var err error
		var cert tls.Certificate
		if cert, err = tls.LoadX509KeyPair(c.TLS.Cert, c.TLS.Key); err != nil {
			return conf, fmt.Errorf("failed to read x509 cert and key pair: %v", err)
		}
		TLS.Certificates = append(TLS.Certificates, cert)
		conf.tls = &TLS
	}

	if !c.Direct {
		callback, err := url.Parse(c.Callback)
		if err != nil {
			return conf, fmt.Errorf("failed to parse callback url")
		}
		conf.callback = *callback
	}
	return conf, nil
}
