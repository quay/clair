package webhook

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// Config provides configuration for an Webhook deliverer.
type Config struct {
	// the URL where our webhook will be delivered
	Target string `yaml:"target" json:"target"`
	target *url.URL
	// the callback url where notifications can be received
	// the notification will be appended to this url
	Callback string `yaml:"callback" json:"callback"`
	callback *url.URL
	// any http headers necessary for the request to Target
	Headers http.Header `yaml:"headers" json:"headers"`
	// whether the webhook deliverer will sign out going.
	// if true webhooks will be sent with a jwt signed by
	// the notifier's private key.
	Signed bool `yaml:"signed" json:"signed"`
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
