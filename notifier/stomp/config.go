package stomp

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/url"
)

type TLS struct {
	// The filesystem path where a root CA can be read.
	RootCA string `yaml:"root_ca"`
	// The filesystem path where a tls certificate can be read.
	Cert string `yaml:"cert"`
	// The filesystem path where a tls private key can be read.
	Key string `yaml:"key"`
}

type Login struct {
	Login    string `yaml:"login"`
	Passcode string `yaml:"passcode"`
}

type Config struct {
	// Configures the STOMP delivery to deliver notifications directly to
	// the configured Destination.
	//
	// If true "Callback" is ignored.
	// If false a notifier.Callback is delivered to the queue and clients
	// utilize the pagination API to retrieve.
	Direct bool `yaml:"direct"`
	// Specifies the number of notifications delivered in single STOMP message
	// when Direct is true.
	//
	// Ignored if Direct is not true
	// If 0 or 1 is provided no rollup occurs and each notification is delivered
	// separately.
	Rollup int `yaml:"rollup"`
	// The callback url where notifications are retrieved.
	Callback string `yaml:"callback"`
	callback url.URL
	// the destination messages will be delivered to
	Destination string `yaml:"destination"`
	// a list of URIs to send messages to.
	// a linear search of this list is always performed.
	URIs []string `yaml:"uris"`
	// optional tls portion of config
	TLS *TLS `yaml:"tls"`
	tls *tls.Config
	// optional user login portion of config
	Login *Login `yaml:"user"`
}

func (c *Config) Validate() (Config, error) {
	conf := *c

	if !c.Direct {
		var u *url.URL
		var err error
		if u, err = url.Parse(c.Callback); err != nil {
			return conf, fmt.Errorf("direct delivery is disabled but callback url could not be parsed.")
		}
		conf.callback = *u
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

	return conf, nil
}
