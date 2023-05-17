package config

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"time"
)

// Notifier provides Clair Notifier node configuration
type Notifier struct {
	// Only one of the following should be provided in the configuration
	//
	// Configures the notifier for webhook delivery
	Webhook *Webhook `yaml:"webhook,omitempty" json:"webhook,omitempty"`
	// Configures the notifier for AMQP delivery.
	AMQP *AMQP `yaml:"amqp,omitempty" json:"amqp,omitempty"`
	// Configures the notifier for STOMP delivery.
	STOMP *STOMP `yaml:"stomp,omitempty" json:"stomp,omitempty"`
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
	PollInterval Duration `yaml:"poll_interval,omitempty" json:"poll_interval,omitempty"`
	// A time.ParseDuration parsable string
	//
	// The frequency at which the notifier attempt delivery of created or previously failed
	// notifications
	// If a value smaller then 1 second is provided it will be replaced with the
	// default 5 second delivery interval.
	DeliveryInterval Duration `yaml:"delivery_interval,omitempty" json:"delivery_interval,omitempty"`
	// DisableSummary disables summarizing vulnerabilities per-manifest.
	//
	// The default is to summarize any new vulnerabilities to the most severe
	// one, in the thought that any additional processing for end-user
	// notifications can have policies around severity and fetch a complete
	// VulnerabilityReport if it'd like.
	//
	// For a machine-consumption use case, it may be easier to instead have the
	// notifier push all the data.
	DisableSummary bool `yaml:"disable_summary,omitempty" json:"disable_summary,omitempty"`
	// A "true" or "false" value
	//
	// Whether Notifier nodes handle migrations to their database.
	Migrations bool `yaml:"migrations,omitempty" json:"migrations,omitempty"`
}

func (n *Notifier) validate(mode Mode) ([]Warning, error) {
	if mode != ComboMode && mode != NotifierMode {
		return nil, nil
	}
	if n.PollInterval < Duration(1*time.Second) {
		n.PollInterval = Duration(DefaultNotifierPollInterval)
	}
	if n.DeliveryInterval < Duration(1*time.Second) {
		n.DeliveryInterval = Duration(DefaultNotifierDeliveryInterval)
	}
	switch mode {
	case ComboMode:
	case NotifierMode:
		if n.IndexerAddr == "" {
			return nil, fmt.Errorf("notifier mode requires a remote Indexer")
		}
		if n.MatcherAddr == "" {
			return nil, fmt.Errorf("notifier mode requires a remote Matcher")
		}
	default:
		panic("programmer error")
	}
	return n.lint()
}

func (n *Notifier) lint() (ws []Warning, err error) {
	ws, err = checkDSN(n.ConnString)
	if err != nil {
		return ws, err
	}
	for i := range ws {
		ws[i].path = ".connstring"
	}
	got := 0
	if n.AMQP != nil {
		got++
	}
	if n.STOMP != nil {
		got++
	}
	if n.Webhook != nil {
		got++
	}
	switch {
	case got == 0 && !reflect.ValueOf(n).Elem().IsZero():
		ws = append(ws, Warning{
			msg: "no delivery mechanisms specified",
		})
	case got > 1:
		ws = append(ws, Warning{
			msg: "multiple delivery mechanisms specified",
		})
	}

	if n.PollInterval < Duration(DefaultNotifierPollInterval) {
		ws = append(ws, Warning{
			path: ".poll_interval",
			msg:  "interval is very fast: may result in increased workload",
		})
	}
	if n.DeliveryInterval < Duration(DefaultNotifierDeliveryInterval) {
		ws = append(ws, Warning{
			path: ".delivery_interval",
			msg:  "interval is very fast: may result in increased workload",
		})
	}
	if n.DisableSummary {
		ws = append(ws, Warning{
			path: ".disable_summary",
			msg:  "disabling notification summary significantly increases memory consumption",
		})
	}

	return ws, nil
}

// Webhook configures the "webhook" notification mechanism.
type Webhook struct {
	// any HTTP headers necessary for the request to Target
	Headers http.Header `yaml:"headers,omitempty" json:"headers,omitempty"`
	// the URL where our webhook will be delivered
	Target string `yaml:"target" json:"target"`
	// the callback url where notifications can be received
	// the notification will be appended to this url
	Callback string `yaml:"callback" json:"callback"`
	// whether the webhook deliverer will sign out going.
	// if true webhooks will be sent with a jwt signed by
	// the notifier's private key.
	Signed bool `yaml:"signed,omitempty" json:"signed,omitempty"`
}

// Validate will return a copy of the Config on success.
// If any validation fails an error will be returned.
func (w *Webhook) validate(mode Mode) ([]Warning, error) {
	if mode != ComboMode && mode != NotifierMode {
		return nil, nil
	}
	var ws []Warning
	if _, err := url.Parse(w.Target); err != nil {
		return nil, fmt.Errorf("failed to parse target url: %w", err)
	}

	// Require trailing slash so url.Parse() can easily append notification id.
	if !strings.HasSuffix(w.Callback, "/") {
		w.Callback = w.Callback + "/"
		ws = append(ws, Warning{
			path: ".callback",
			msg:  `URL should end in a "/"`,
		})
	}

	if _, err := url.Parse(w.Callback); err != nil {
		return nil, fmt.Errorf("failed to parse callback url: %w", err)
	}
	ls, err := w.lint()
	ws = append(ws, ls...)
	if err != nil {
		return ws, err
	}
	return ws, nil
}

func (w *Webhook) lint() ([]Warning, error) {
	if w.Signed {
		return []Warning{{
			path:  ".signed",
			inner: ErrDeprecated,
		}}, nil
	}
	return nil, nil
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
	Durable bool `yaml:"durability,omitempty" json:"durability,omitempty"`
	// Whether bound consumers define the lifecycle of the Exchange.
	AutoDelete bool `yaml:"auto_delete,omitempty" json:"auto_delete,omitempty"`
}

func (e *Exchange) validate(_ Mode) ([]Warning, error) {
	if e.Type == "" {
		return nil, fmt.Errorf("field required")
	}
	return nil, nil
}

// AMQP configures the AMQP notification mechanism.
type AMQP struct {
	TLS *TLS `yaml:"tls,omitempty" json:"tls,omitempty"`
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
	Rollup int `yaml:"rollup,omitempty" json:"rollup,omitempty"`
	// AMQPConfigures the AMQP delivery to deliver notifications directly to
	// the configured Exchange.
	//
	// If true "Callback" is ignored.
	// If false a notifier.Callback is delivered to the queue and clients
	// utilize the pagination API to retrieve.
	Direct bool `yaml:"direct,omitempty" json:"direct,omitempty"`
}

// Validate confirms configuration is valid.
func (c *AMQP) validate(mode Mode) ([]Warning, error) {
	if mode != ComboMode && mode != NotifierMode {
		return nil, nil
	}
	var ws []Warning
	if c.RoutingKey == "" {
		return nil, fmt.Errorf("AMQP config requires the routing key field")
	}
	if len(c.URIs) == 0 {
		return nil, fmt.Errorf("missing URIs for AMQP broker")
	}
	for _, uri := range c.URIs {
		if _, err := url.Parse(uri); err != nil {
			return nil, fmt.Errorf("invalid URI %q: %w", uri, err)
		}
	}

	if !c.Direct {
		if !strings.HasSuffix(c.Callback, "/") {
			c.Callback = c.Callback + "/"
			ws = append(ws, Warning{
				path: ".callback",
				msg:  `URL should end in a "/"`,
			})
		}
		if _, err := url.Parse(c.Callback); err != nil {
			return nil, fmt.Errorf("failed to parse callback url: %w", err)
		}
	}
	ls, err := c.lint()
	ws = append(ws, ls...)
	if err != nil {
		return ws, err
	}
	return ws, nil
}

func (c *AMQP) lint() (w []Warning, err error) {
	if c.Rollup == 1 {
		w = append(w, Warning{
			msg: "`Rollup` set to 1: this means nothing",
		})
	}
	if c.Direct && c.Callback != "" {
		w = append(w, Warning{
			msg: "`Callback` and `Direct` set: `Callback` will be ignored",
		})
	}
	return w, nil
}

// Login is the login details for a STOMP broker.
type Login struct {
	Login    string `yaml:"login" json:"login"`
	Passcode string `yaml:"passcode" json:"passcode"`
}

// STOMP configures the STOMP notification mechanism.
type STOMP struct {
	// optional tls portion of config
	TLS *TLS `yaml:"tls,omitempty" json:"tls,omitempty"`
	// optional user login portion of config
	Login *Login `yaml:"user,omitempty" json:"user,omitempty"`
	// The callback url where notifications are retrieved.
	Callback string `yaml:"callback" json:"callback"`
	// the destination messages will be delivered to
	Destination string `yaml:"destination" json:"destination"`
	// a list of URIs to send messages to.
	// a linear search of this list is always performed.
	//
	// Note that "URI" is a misnomer, this must be host:port pairs.
	URIs []string `yaml:"uris" json:"uris"`
	// Specifies the number of notifications delivered in single STOMP message
	// when Direct is true.
	//
	// Ignored if Direct is not true
	// If 0 or 1 is provided no rollup occurs and each notification is delivered
	// separately.
	Rollup int `yaml:"rollup,omitempty" json:"rollup,omitempty"`
	// Configures the STOMP delivery to deliver notifications directly to
	// the configured Destination.
	//
	// If true "Callback" is ignored.
	// If false a notifier.Callback is delivered to the queue and clients
	// utilize the pagination API to retrieve.
	Direct bool `yaml:"direct,omitempty" json:"direct,omitempty"`
}

func (c *STOMP) validate(mode Mode) ([]Warning, error) {
	if mode != ComboMode && mode != NotifierMode {
		return nil, nil
	}
	var ws []Warning
	if len(c.URIs) == 0 {
		return nil, fmt.Errorf("missing URIs for STOMP broker")
	}
	for _, u := range c.URIs {
		if _, _, err := net.SplitHostPort(u); err != nil {
			return nil, fmt.Errorf("bad host:port %q: %w", u, err)
		}
	}
	if !c.Direct {
		if !strings.HasSuffix(c.Callback, "/") {
			c.Callback = c.Callback + "/"
			ws = append(ws, Warning{
				path: ".callback",
				msg:  `URL should end in a "/"`,
			})
		}
		if _, err := url.Parse(c.Callback); err != nil {
			return nil, fmt.Errorf("failed to parse callback url: %w", err)
		}
	}
	ls, err := c.lint()
	ws = append(ws, ls...)
	if err != nil {
		return ws, err
	}
	return ws, nil
}

func (c *STOMP) lint() (w []Warning, err error) {
	if c.Rollup == 1 {
		w = append(w, Warning{
			msg: "`Rollup` set to 1: this means nothing",
		})
	}
	if c.Direct && c.Callback != "" {
		w = append(w, Warning{
			msg: "`Callback` and `Direct` set: `Callback` will be ignored",
		})
	}
	return w, nil
}
