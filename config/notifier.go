package config

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/quay/clair/v4/notifier/amqp"
	"github.com/quay/clair/v4/notifier/stomp"
	"github.com/quay/clair/v4/notifier/webhook"
)

// Notifier provides Clair Notifier node configuration
type Notifier struct {
	// A Postgres connection string.
	//
	// Formats:
	// url: "postgres://pqgotest:password@localhost/pqgotest?sslmode=verify-full"
	// or
	// string: "user=pqgotest dbname=pqgotest sslmode=verify-full"
	ConnString string `yaml:"connstring" json:"connstring"`
	// A string in <host>:<port> format where <host> can be an empty string.
	//
	// A Notifier contacts an Indexer to create obtain manifests affected by vulnerabilities.
	// The location of this Indexer is required.
	IndexerAddr string `yaml:"indexer_addr" json:"indexer_addr"`
	// A string in <host>:<port> format where <host> can be an empty string.
	//
	// A Notifier contacts a Matcher to list update operations and acquire diffs.
	// The location of this Indexer is required.
	MatcherAddr string `yaml:"matcher_addr" json:"matcher_addr"`
	// A time.ParseDuration parsable string
	//
	// The frequency at which the notifier will query at Matcher for Update Operations.
	// If a value smaller then 1 second is provided it will be replaced with the
	// default 5 second poll interval.
	PollInterval time.Duration `yaml:"poll_interval" json:"poll_interval"`
	// A time.ParseDuration parsable string
	//
	// The frequency at which the notifier attempt delivery of created or previously failed
	// notifications
	// If a value smaller then 1 second is provided it will be replaced with the
	// default 5 second delivery interval.
	DeliveryInterval time.Duration `yaml:"delivery_interval" json:"delivery_interval"`
	// DisableSummary disables summarizing vulnerabilities per-manifest.
	//
	// The default is to summarize any new vulnerabilities to the most severe
	// one, in the thought that any additional processing for end-user
	// notifications can have policies around severity and fetch a complete
	// VulnerabilityReport if it'd like.
	//
	// For a machine-consumption use case, it may be easier to instead have the
	// notifier push all the data.
	DisableSummary bool `yaml:"disable_summary" json:"disable_summary"`
	// Only one of the following should be provided in the configuration
	//
	// Configures the notifier for webhook delivery
	Webhook *webhook.Config `yaml:"webhook" json:"webhook"`
	// Configures the notifier for AMQP delivery.
	AMQP *amqp.Config `yaml:"amqp" json:"amqp"`
	// Configures the notifier for STOMP delivery.
	STOMP *stomp.Config `yaml:"stomp" json:"stomp"`
	// A "true" or "false" value
	//
	// Whether Notifier nodes handle migrations to their database.
	Migrations bool `yaml:"migrations" json:"migrations"`
}

func (n *Notifier) Validate(combo bool) error {
	const (
		DefaultPollInterval     = 5 * time.Second
		DefaultDeliveryInterval = 5 * time.Second
	)
	if n.ConnString == "" {
		return fmt.Errorf("notifier mode requires a database connection string")
	}
	if n.PollInterval < 1*time.Second {
		n.PollInterval = DefaultPollInterval
	}
	if n.DeliveryInterval < 1*time.Second {
		n.DeliveryInterval = DefaultDeliveryInterval
	}
	if !combo {
		if n.IndexerAddr == "" {
			return fmt.Errorf("notifier mode requires a remote Indexer")
		}
		if n.MatcherAddr == "" {
			return fmt.Errorf("notifier mode requires a remote Matcher")
		}
	}
	return nil
}

type Webhook struct {
	// any HTTP headers necessary for the request to Target
	Headers http.Header `yaml:"headers" json:"headers"`
	// the URL where our webhook will be delivered
	Target string `yaml:"target" json:"target"`
	// the callback url where notifications can be received
	// the notification will be appended to this url
	Callback string `yaml:"callback" json:"callback"`
	// whether the webhook deliverer will sign out going.
	// if true webhooks will be sent with a jwt signed by
	// the notifier's private key.
	Signed bool `yaml:"signed" json:"signed"`
}

// Validate will return a copy of the Config on success.
// If any validation fails an error will be returned.
func (c *Webhook) Validate() error {
	if _, err := url.Parse(c.Target); err != nil {
		return fmt.Errorf("failed to parse target url")
	}

	// Require trailing slash so url.Parse() can easily append notification id.
	if !strings.HasSuffix(c.Callback, "/") {
		c.Callback = c.Callback + "/"
	}

	if _, err := url.Parse(c.Callback); err != nil {
		return fmt.Errorf("failed to parse callback url: %w", err)
	}

	return nil
}

// Exchange are the required fields necessary to check
// the existence of an Exchange
//
// For more details see: https://godoc.org/github.com/streadway/amqp#Channel.ExchangeDeclarePassive
type Exchange struct {
	// The name of the exchange
	Name string `yaml:"name" json:"name"`
	// The type of the exchange. Typically:
	// "direct"
	// "fanout"
	// "topic"
	// "headers"
	Type string `yaml:"type" json:"type"`
	// Whether the exchange survives server restarts
	Durable bool `yaml:"durability" json:"durability"`
	// Whether bound consumers define the lifecycle of the Exchange.
	AutoDelete bool `yaml:"auto_delete" json:"auto_delete"`
}

// AMQP provides configuration for an AMQP deliverer.
type AMQP struct {
	TLS *TLS `yaml:"tls" json:"tls"`
	// The AMQP exchange notifications will be delivered to.
	// A passive declare is performed and if the exchange does not exist
	// the declare will fail.
	Exchange Exchange `yaml:"exchange" json:"exchange"`
	// The routing key used to route notifications to the desired queue.
	RoutingKey string `yaml:"routing_key" json:"routing_key"`
	// The callback url where notifications are retrieved.
	Callback string `yaml:"callback" json:"callback"`
	// A list of AMQP compliant URI scheme. see: https://www.rabbitmq.com/uri-spec.html
	// example: "amqp://user:pass@host:10000/vhost"
	//
	// The first successful connection will be used by the amqp deliverer.
	//
	// If "amqps://" broker URI schemas are provided the TLS configuration below is required.
	URIs []string `yaml:"uris" json:"uris"`
	// Specifies the number of notifications delivered in single AMQP message
	// when Direct is true.
	//
	// Ignored if Direct is not true
	// If 0 or 1 is provided no rollup occurs and each notification is delivered
	// separately.
	Rollup int `yaml:"rollup" json:"rollup"`
	// AMQPConfigures the AMQP delivery to deliver notifications directly to
	// the configured Exchange.
	//
	// If true "Callback" is ignored.
	// If false a notifier.Callback is delivered to the queue and clients
	// utilize the pagination API to retrieve.
	Direct bool `yaml:"direct" json:"direct"`
}

// Validate confirms configuration is valid.
func (c *AMQP) Validate() error {
	if c.Exchange.Type == "" {
		return fmt.Errorf("AMQP config requires the exchange.type field")
	}
	if c.RoutingKey == "" {
		return fmt.Errorf("AMQP config requires the routing key field")
	}
	for _, uri := range c.URIs {
		if strings.HasPrefix(uri, "amqps://") {
			if c.TLS.RootCA == "" {
				return fmt.Errorf("amqps:// broker requires tls_root_ca")
			}
			if c.TLS.Cert == "" {
				return fmt.Errorf("amqps:// broker requires tls_cert")
			}
			if c.TLS.Key == "" {
				return fmt.Errorf("amqps:// broker requires tls_key")
			}
		}
	}

	if c.TLS != nil {
		if c.TLS.Cert == "" || c.TLS.Key == "" {
			return fmt.Errorf("both tls cert and key are required")
		}
	}

	if !c.Direct {
		if !strings.HasSuffix(c.Callback, "/") {
			c.Callback = c.Callback + "/"
		}
		if _, err := url.Parse(c.Callback); err != nil {
			return fmt.Errorf("failed to parse callback url: %w", err)
		}
	}
	return nil
}

type Login struct {
	Login    string `yaml:"login" json:"login"`
	Passcode string `yaml:"passcode" json:"passcode"`
}

type STOMP struct {
	// optional tls portion of config
	TLS *TLS `yaml:"tls" json:"tls"`
	// optional user login portion of config
	Login *Login `yaml:"user" json:"user"`
	// The callback url where notifications are retrieved.
	Callback string `yaml:"callback" json:"callback"`
	// the destination messages will be delivered to
	Destination string `yaml:"destination" json:"destination"`
	// a list of URIs to send messages to.
	// a linear search of this list is always performed.
	URIs []string `yaml:"uris" json:"uris"`
	// Specifies the number of notifications delivered in single STOMP message
	// when Direct is true.
	//
	// Ignored if Direct is not true
	// If 0 or 1 is provided no rollup occurs and each notification is delivered
	// separately.
	Rollup int `yaml:"rollup" json:"rollup"`
	// Configures the STOMP delivery to deliver notifications directly to
	// the configured Destination.
	//
	// If true "Callback" is ignored.
	// If false a notifier.Callback is delivered to the queue and clients
	// utilize the pagination API to retrieve.
	Direct bool `yaml:"direct" json:"direct"`
}

func (c *STOMP) Validate() error {
	if !c.Direct {
		if !strings.HasSuffix(c.Callback, "/") {
			c.Callback = c.Callback + "/"
		}
		if _, err := url.Parse(c.Callback); err != nil {
			return fmt.Errorf("failed to parse callback url: %w", err)
		}
	}
	if c.TLS != nil {
		if c.TLS.Cert == "" || c.TLS.Key == "" {
			return fmt.Errorf("both tls cert and key are required")
		}
	}
	return nil
}
