package webhook

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// Config provides configuration for an Webhook deliverer.
type Config struct {
	// Target is the URL where our webhook will be delivered.
	Target string `yaml:"target" json:"target"`
	target *url.URL
	// Callback is the URL where notifications can be retrieved.
	//
	// The notification ID will be appended to this URL, so it should have a
	// trailing slash.
	Callback string `yaml:"callback" json:"callback"`
	callback *url.URL
	// Headers are any HTTP headers necessary for the request to Target.
	Headers http.Header `yaml:"headers" json:"headers"`
	// Signed indicates whether the webhook deliverer will sign outgoing
	// requests. If true, webhooks will be sent with a jwt signed by the
	// notifier's private key.
	//
	// Deprecated: Signed exists for documentation purposes only and has no
	// effect. The code it controlled was removed between versions 4.0 and 4.1.
	Signed bool `yaml:"signed,omitempty" json:"signed,omitempty"`
}

// Validate will return a copy of the Config on success.
// If any validation fails an error will be returned.
func (c *Config) Validate() (Config, error) {
	conf := *c
	target, err := url.Parse(c.Target)
	if err != nil {
		return conf, fmt.Errorf("failed to parse target url")
	}
	conf.target = target

	// require trailing slash so url.Parse() can easily
	// append notification id.
	if !strings.HasSuffix(c.Callback, "/") {
		c.Callback = c.Callback + "/"
	}

	callback, err := url.Parse(c.Callback)
	if err != nil {
		return conf, fmt.Errorf("failed to parse callback url")
	}
	conf.callback = callback

	if conf.Headers == nil {
		conf.Headers = map[string][]string{}
	}
	conf.Headers.Set("Content-Type", "application/json")

	return conf, nil
}
